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
package org.onosproject.incubator.net.domain;

import com.google.common.annotations.Beta;

/**
 * The abstract base class for the resource that satisfies an intent primitive.
 */
@Beta
public abstract class IntentResource {

    private final IntentPrimitive primitive;

    // TODO add other common fields
    //String ingressTag;
    //String egressTag;
    //etc.

    IntentResource(IntentPrimitive primitive) {
        this.primitive = primitive;
    }

    public IntentPrimitive primitive() {
        return primitive;
    }

}
