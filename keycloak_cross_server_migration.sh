#!/bin/bash

# Source Keycloak Configuration
SOURCE_KEYCLOAK_URL="https://ubuntukeycloak.enum.africa"
SOURCE_ADMIN_USER="admin"
SOURCE_ADMIN_PASSWORD=""
SOURCE_REALM="enum-dev"

# Target Keycloak Configuration
TARGET_KEYCLOAK_URL="http://localhost:8080"
TARGET_ADMIN_USER="admin"
TARGET_ADMIN_PASSWORD="admin"
TARGET_REALM="wapp-enum"

# Common Configuration
KC_BIN="/mnt/c/Users/DELL/Downloads/Keycloak-26.2.4/keycloak-26.2.4/bin/kcadm.sh"
TEMP_DIR="./temp_export"
EXPORT_FILE="$TEMP_DIR/realm_export.json"

# Check prerequisites
if [ ! -f "$KC_BIN" ]; then
    echo "❌ Error: kcadm.sh not found at $KC_BIN"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "❌ Error: jq is not installed. Install with: sudo apt-get install jq"
    exit 1
fi

# Initialize environment
mkdir -p "$TEMP_DIR"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Enhanced login function with retries
keycloak_login() {
    local url=$1 user=$2 password=$3 realm=$4
    for i in {1..3}; do
        if $KC_BIN config credentials --server "$url" --realm "$realm" --user "$user" --password "$password"; then
            return 0
        fi
        sleep 2
    done
    echo "❌ Failed to login after 3 attempts"
    return 1
}

# Source Keycloak login
source_login() {
    echo "🔐 Logging into Source Keycloak..."
    keycloak_login "$SOURCE_KEYCLOAK_URL" "$SOURCE_ADMIN_USER" "$SOURCE_ADMIN_PASSWORD" "master" || exit 1
}

# Target Keycloak login
target_login() {
    echo "🔐 Logging into Target Keycloak..."
    keycloak_login "$TARGET_KEYCLOAK_URL" "$TARGET_ADMIN_USER" "$TARGET_ADMIN_PASSWORD" "master" || exit 1
}

# Export entire realm from source
export_realm() {
    echo "📤 Exporting source realm..."
    source_login
    $KC_BIN get realms/"$SOURCE_REALM" > "$EXPORT_FILE" || {
        echo "❌ Failed to export realm $SOURCE_REALM"
        exit 1
    }
}

# Create target realm
create_realm() {
    echo "🏗️ Creating target realm..."
    target_login
    
    if $KC_BIN get realms/"$TARGET_REALM" &>/dev/null; then
        echo "⚠️ Realm $TARGET_REALM already exists, skipping creation..."
        return 0
    fi
    
    jq 'del(.id, .realm)' "$EXPORT_FILE" > "$TEMP_DIR/realm_settings.json"
    $KC_BIN create realms -f "$TEMP_DIR/realm_settings.json" || {
        echo "❌ Failed to create realm $TARGET_REALM"
        exit 1
    }
    echo "✅ Created realm $TARGET_REALM"
}

# Migrate all roles first
migrate_roles() {
    echo "🎭 Migrating all realm roles..."
    source_login
    
    # Get all roles from source
    $KC_BIN get roles -r "$SOURCE_REALM" > "$TEMP_DIR/source_roles.json"
    
    target_login
    $KC_BIN get roles -r "$TARGET_REALM" > "$TEMP_DIR/target_roles.json"
    
    # Create missing roles
    jq -c '.[]' "$TEMP_DIR/source_roles.json" | while read role; do
        roleName=$(echo "$role" | jq -r '.name')
        roleId=$(echo "$role" | jq -r '.id')
        
        # Check if role exists in target
        if ! jq -e --arg name "$roleName" '.[] | select(.name == $name)' "$TEMP_DIR/target_roles.json" >/dev/null; then
            echo "$role" | jq 'del(.id)' > "$TEMP_DIR/role.json"
            $KC_BIN create roles -r "$TARGET_REALM" -f "$TEMP_DIR/role.json" && {
                echo "✅ Created role: $roleName"
                # Store mapping between source and target role IDs
                targetRoleId=$($KC_BIN get roles/"$roleName" -r "$TARGET_REALM" | jq -r '.id')
                echo "$roleId $targetRoleId" >> "$TEMP_DIR/role_mappings.txt"
            } || {
                echo "⚠️ Failed to create role: $roleName"
            }
        else
            echo "⚠️ Role $roleName already exists, skipping creation..."
            # Still store the mapping for existing roles
            targetRoleId=$($KC_BIN get roles/"$roleName" -r "$TARGET_REALM" | jq -r '.id')
            echo "$roleId $targetRoleId" >> "$TEMP_DIR/role_mappings.txt"
        fi
    done
}

# Migrate users with all role mappings
migrate_users() {
    echo "👤 Migrating users with all role mappings..."
    source_login
    
    # Get all users from source
    $KC_BIN get users -r "$SOURCE_REALM" | jq -c '.[]' | while read user; do
        username=$(echo "$user" | jq -r '.username')
        userId=$(echo "$user" | jq -r '.id')
        
        target_login
        exists=$($KC_BIN get users -r "$TARGET_REALM" -q "username=$username" | jq -r '.[0].id')
        
        if [ "$exists" != "null" ]; then
            echo "⚠️ User $username already exists, skipping..."
            continue
        fi
        
        # Create user without credentials first
        echo "$user" | jq 'del(.id, .createdTimestamp, .federatedIdentities)' > "$TEMP_DIR/user.json"
        $KC_BIN create users -r "$TARGET_REALM" -f "$TEMP_DIR/user.json" || {
            echo "❌ Failed to create user $username"
            continue
        }
        echo "✅ Created user: $username"
        
        # Get new user ID
        newUserId=$($KC_BIN get users -r "$TARGET_REALM" -q "username=$username" | jq -r '.[0].id')
        
        # Migrate password if exists
        if [ "$(echo "$user" | jq '.credentials | length')" -gt 0 ]; then
            password=$(echo "$user" | jq -r '.credentials[0].value')
            $KC_BIN set-password -r "$TARGET_REALM" --username "$username" --new-password "$password" || {
                echo "⚠️ Failed to set password for user $username"
            }
        fi
        
        # Migrate all role mappings (realm and client)
        migrate_user_role_mappings "$userId" "$newUserId" "$username"
    done
}

# Function to migrate all role mappings for a user
migrate_user_role_mappings() {
    local sourceUserId=$1 targetUserId=$2 username=$3
    
    echo "🔄 Processing role mappings for user $username..."
    
    # Migrate realm role mappings
    source_login
    $KC_BIN get users/"$sourceUserId"/role-mappings/realm -r "$SOURCE_REALM" > "$TEMP_DIR/realm_role_mappings.json"
    
    if [ -s "$TEMP_DIR/realm_role_mappings.json" ]; then
        target_login
        
        # Process each realm role mapping
        jq -c '.[]' "$TEMP_DIR/realm_role_mappings.json" | while read roleMapping; do
            roleName=$(echo "$roleMapping" | jq -r '.name')
            
            # Verify role exists in target
            target_login
            roleExists=$($KC_BIN get roles/"$roleName" -r "$TARGET_REALM" &>/dev/null; echo $?)
            
            if [ "$roleExists" -eq 0 ]; then
                echo "$roleMapping" | jq 'del(.id)' > "$TEMP_DIR/single_role_mapping.json"
                $KC_BIN create users/"$targetUserId"/role-mappings/realm -r "$TARGET_REALM" -f "$TEMP_DIR/single_role_mapping.json" && {
                    echo "✅ Mapped realm role $roleName to user $username"
                } || {
                    echo "⚠️ Failed to map realm role $roleName to user $username"
                }
            else
                echo "⚠️ Realm role $roleName not found in target realm, skipping mapping"
            fi
        done
    fi
    
    # Migrate client role mappings
    source_login
    $KC_BIN get clients -r "$SOURCE_REALM" | jq -c '.[]' | while read client; do
        clientId=$(echo "$client" | jq -r '.id')
        clientName=$(echo "$client" | jq -r '.clientId')
        
        # Get client role mappings from source
        $KC_BIN get users/"$sourceUserId"/role-mappings/clients/"$clientId" -r "$SOURCE_REALM" > "$TEMP_DIR/client_role_mappings.json"
        
        if [ -s "$TEMP_DIR/client_role_mappings.json" ]; then
            target_login
            
            # Find corresponding client in target
            targetClientId=$($KC_BIN get clients -r "$TARGET_REALM" -q "clientId=$clientName" | jq -r '.[0].id')
            
            if [ "$targetClientId" != "null" ]; then
                # Process each client role mapping
                jq -c '.[]' "$TEMP_DIR/client_role_mappings.json" | while read roleMapping; do
                    roleName=$(echo "$roleMapping" | jq -r '.name')
                    
                    # Verify role exists in target client
                    target_login
                    roleExists=$($KC_BIN get clients/"$targetClientId"/roles/"$roleName" -r "$TARGET_REALM" &>/dev/null; echo $?)
                    
                    if [ "$roleExists" -eq 0 ]; then
                        echo "$roleMapping" | jq 'del(.id)' > "$TEMP_DIR/single_client_role_mapping.json"
                        $KC_BIN create users/"$targetUserId"/role-mappings/clients/"$targetClientId" -r "$TARGET_REALM" -f "$TEMP_DIR/single_client_role_mapping.json" && {
                            echo "✅ Mapped client role $roleName (client: $clientName) to user $username"
                        } || {
                            echo "⚠️ Failed to map client role $roleName (client: $clientName) to user $username"
                        }
                    else
                        echo "⚠️ Client role $roleName (client: $clientName) not found in target realm, skipping mapping"
                    fi
                done
            else
                echo "⚠️ Client $clientName not found in target realm, skipping client role mappings"
            fi
        fi
    done
}

# Other migration functions (similar to previous versions)
migrate_client_scopes() {
    echo "🔧 Migrating client scopes..."
    source_login
    $KC_BIN get client-scopes -r "$SOURCE_REALM" | jq -c '.[]' | while read scope; do
        scopeName=$(echo "$scope" | jq -r '.name')
        
        target_login
        if $KC_BIN get client-scopes -r "$TARGET_REALM" -q "name=$scopeName" | jq -r '.[0].id' | grep -q -v "null"; then
            echo "⚠️ Client scope $scopeName already exists, skipping..."
        else
            echo "$scope" | jq 'del(.id)' > "$TEMP_DIR/client_scope.json"
            $KC_BIN create client-scopes -r "$TARGET_REALM" -f "$TEMP_DIR/client_scope.json" || {
                echo "❌ Failed to create client scope $scopeName"
                continue
            }
            echo "✅ Created client scope: $scopeName"
        fi
    done
}

migrate_clients() {
    echo "🚀 Migrating clients..."
    source_login
    $KC_BIN get clients -r "$SOURCE_REALM" | jq -c '.[]' | while read client; do
        clientId=$(echo "$client" | jq -r '.clientId')
        
        target_login
        exists=$($KC_BIN get clients -r "$TARGET_REALM" -q "clientId=$clientId" | jq -r '.[0].id')
        
        if [ "$exists" != "null" ]; then
            echo "⚠️ Client $clientId already exists, skipping..."
        else
            echo "$client" | jq 'del(.id)' > "$TEMP_DIR/client.json"
            
            # Create client
            $KC_BIN create clients -r "$TARGET_REALM" -f "$TEMP_DIR/client.json" || {
                echo "❌ Failed to create client $clientId"
                continue
            }
            echo "✅ Created client: $clientId"
            
            # Get new client ID
            newClientId=$($KC_BIN get clients -r "$TARGET_REALM" -q "clientId=$clientId" | jq -r '.[0].id')
            
            # Migrate client scope mappings
            echo "$client" | jq '.scopeMappings' > "$TEMP_DIR/scope_mappings.json"
            if [ "$(jq length "$TEMP_DIR/scope_mappings.json")" -gt 0 ]; then
                $KC_BIN update clients/"$newClientId"/scope-mappings/realm -r "$TARGET_REALM" -f "$TEMP_DIR/scope_mappings.json" || {
                    echo "⚠️ Failed to add scope mappings for client $clientId"
                }
            fi
        fi
    done
}

migrate_groups() {
    echo "👥 Migrating groups..."
    source_login
    $KC_BIN get groups -r "$SOURCE_REALM" | jq -c '.[]' | while read group; do
        groupName=$(echo "$group" | jq -r '.name')
        
        target_login
        exists=$($KC_BIN get groups -r "$TARGET_REALM" -q "search=$groupName" | jq -r '.[0].id')
        
        if [ "$exists" != "null" ]; then
            echo "⚠️ Group $groupName already exists, skipping..."
        else
            echo "$group" | jq 'del(.id, .path, .subGroupCount)' > "$TEMP_DIR/group.json"
            $KC_BIN create groups -r "$TARGET_REALM" -f "$TEMP_DIR/group.json" || {
                echo "❌ Failed to create group $groupName"
                continue
            }
            echo "✅ Created group: $groupName"
            
            # Get new group ID
            newGroupId=$($KC_BIN get groups -r "$TARGET_REALM" -q "search=$groupName" | jq -r '.[0].id')
            
            # Migrate role mappings
            source_login
            groupId=$(echo "$group" | jq -r '.id')
            $KC_BIN get groups/"$groupId"/role-mappings/realm -r "$SOURCE_REALM" > "$TEMP_DIR/role_mappings.json"
            if [ "$(jq length "$TEMP_DIR/role_mappings.json")" -gt 0 ]; then
                target_login
                $KC_BIN create groups/"$newGroupId"/role-mappings/realm -r "$TARGET_REALM" -f "$TEMP_DIR/role_mappings.json" || {
                    echo "⚠️ Failed to add role mappings for group $groupName"
                }
            fi
        fi
    done
}

migrate_identity_providers() {
    echo "🌐 Migrating identity providers..."
    source_login
    $KC_BIN get identity-provider/instances -r "$SOURCE_REALM" | jq -c '.[]' | while read idp; do
        alias=$(echo "$idp" | jq -r '.alias')
        
        target_login
        exists=$($KC_BIN get identity-provider/instances -r "$TARGET_REALM" | jq -r ".[] | select(.alias == \"$alias\") | .alias")
        
        if [ -n "$exists" ]; then
            echo "⚠️ Identity provider $alias already exists, skipping..."
        else
            echo "$idp" | jq 'del(.internalId)' > "$TEMP_DIR/idp.json"
            $KC_BIN create identity-provider/instances -r "$TARGET_REALM" -f "$TEMP_DIR/idp.json" || {
                echo "❌ Failed to create identity provider $alias"
                continue
            }
            echo "✅ Created identity provider: $alias"
        fi
    done
}

migrate_realm_settings() {
    echo "⚙️ Migrating realm settings..."
    SETTINGS=(
        "smtpServer" "loginTheme" "accountTheme" "adminTheme" "emailTheme"
        "accessTokenLifespan" "ssoSessionIdleTimeout" "ssoSessionMaxLifespan"
        "offlineSessionIdleTimeout" "rememberMe" "registrationAllowed"
        "registrationEmailAsUsername" "editUsernameAllowed" "resetPasswordAllowed"
        "verifyEmail" "passwordPolicy"
    )
    
    source_login
    jq 'del(.id, .realm)' "$EXPORT_FILE" > "$TEMP_DIR/realm_settings.json"
    
    for setting in "${SETTINGS[@]}"; do
        value=$(jq -r ".${setting}" "$TEMP_DIR/realm_settings.json")
        if [ "$value" != "null" ]; then
            target_login
            $KC_BIN update realms/"$TARGET_REALM" -s "${setting}=$value" || {
                echo "⚠️ Failed to update setting $setting"
            }
            echo "✅ Updated $setting"
        fi
    done
}

# Main migration process
main() {
    echo "🚀 Starting Keycloak migration from $SOURCE_REALM to $TARGET_REALM"
    export_realm
    create_realm
    migrate_roles
    migrate_client_scopes
    migrate_clients
    migrate_groups
    migrate_users
    migrate_identity_providers
    migrate_realm_settings
    echo "🎉 Migration completed successfully!"
}

main