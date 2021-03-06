/*
 * Copyright 2015 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.security;

import org.onosproject.core.Permission;

/**
 * Aids SM-ONOS to perform API-level permission checking.
 */
public final class AppGuard {

    private AppGuard() {
    }

    /**
     * Checks if the caller has the required permission only when security-mode is enabled.
     * @param permission permission to be checked
     */
    public static void checkPermission(Permission permission) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            System.getSecurityManager().checkPermission(new AppPermission(permission.name()));
        }
    }
}
