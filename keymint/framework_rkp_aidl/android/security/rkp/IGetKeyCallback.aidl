/*
 * Copyright (C) 2022 The Android Open Source Project
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

package android.security.rkp;

import android.security.rkp.RemotelyProvisionedKey;

oneway interface IGetKeyCallback {
    enum ErrorCode {
        ERROR_UNKNOWN = 1,
        ERROR_REQUIRES_SECURITY_PATCH = 2,
        ERROR_PENDING_INTERNET_CONNECTIVITY = 3,
        ERROR_PERMANENT = 5,
    }

    void onSuccess(in RemotelyProvisionedKey key);
    void onCancel();
    void onError(ErrorCode error, String description);
}
