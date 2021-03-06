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
package org.onosproject.store.consistent.impl;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import org.onosproject.store.service.AtomicValue;
import org.onosproject.store.service.AtomicValueEvent;
import org.onosproject.store.service.AtomicValueEventListener;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.MapEvent;
import org.onosproject.store.service.MapEventListener;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.Versioned;

/**
 * Default implementation of AtomicValue.
 *
 * @param <V> value type
 */
public class DefaultAtomicValue<V> implements AtomicValue<V> {

    private final Set<AtomicValueEventListener<V>> listeners = new CopyOnWriteArraySet<>();
    private final ConsistentMap<String, byte[]> valueMap;
    private final String name;
    private final Serializer serializer;
    private final MapEventListener<String, byte[]> mapEventListener = new InternalMapEventListener();

    public DefaultAtomicValue(ConsistentMap<String, byte[]> valueMap,
            String name,
            Serializer serializer) {
        this.valueMap = valueMap;
        this.name = name;
        this.serializer = serializer;
    }

    @Override
    public boolean compareAndSet(V expect, V update) {
        if (expect == null) {
            if (update == null) {
                return true;
            }
            return valueMap.putIfAbsent(name, serializer.encode(update)) == null;
        } else {
            if (update == null) {
                return valueMap.remove(name, serializer.encode(expect));
            }
            return valueMap.replace(name, serializer.encode(expect), serializer.encode(update));
        }
    }

    @Override
    public V get() {
        Versioned<byte[]> rawValue = valueMap.get(name);
        return rawValue == null ? null : serializer.decode(rawValue.value());
    }

    @Override
    public V getAndSet(V value) {
        Versioned<byte[]> previousValue = value == null ?
                valueMap.remove(name) : valueMap.put(name, serializer.encode(value));
        return previousValue == null ? null : serializer.decode(previousValue.value());
    }

    @Override
    public void set(V value) {
        getAndSet(value);
    }

    @Override
    public void addListener(AtomicValueEventListener<V> listener) {
        synchronized (listeners) {
            if (listeners.add(listener)) {
                if (listeners.size() == 1) {
                    valueMap.addListener(mapEventListener);
                }
            }
        }
    }

    @Override
    public void removeListener(AtomicValueEventListener<V> listener) {
        synchronized (listeners) {
            if (listeners.remove(listener)) {
                if (listeners.size() == 0) {
                    valueMap.removeListener(mapEventListener);
                }
            }
        }
    }

    private class InternalMapEventListener implements MapEventListener<String, byte[]> {

        @Override
        public void event(MapEvent<String, byte[]> mapEvent) {
            V newValue = mapEvent.type() == MapEvent.Type.REMOVE ? null : serializer.decode(mapEvent.value().value());
            AtomicValueEvent<V> atomicValueEvent = new AtomicValueEvent<>(name, AtomicValueEvent.Type.UPDATE, newValue);
            listeners.forEach(l -> l.event(atomicValueEvent));
        }
    }
}
