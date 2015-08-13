/*
 * Copyright 2014-2015 Open Networking Laboratory
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



package org.onlab.packet;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import static org.onlab.packet.PacketUtils.*;

/**
 *
 */

public class UDP extends BasePacket {
    public static final Map<Integer, Deserializer<? extends IPacket>> PORT_DESERIALIZER_MAP =
            new HashMap<>();
    private static final int MASK = 0xffff;

    public static final int DHCP_SERVER_PORT = (int) 67 & MASK;
    public static final int DHCP_CLIENT_PORT = (int) 68 & MASK;

    private static final short UDP_HEADER_LENGTH = 8;

    static {
        /*
         * Disable DHCP until the deserialize code is hardened to deal with
         * garbage input
         */
        UDP.PORT_DESERIALIZER_MAP.put(UDP.DHCP_SERVER_PORT, DHCP.deserializer());
        UDP.PORT_DESERIALIZER_MAP.put(UDP.DHCP_CLIENT_PORT, DHCP.deserializer());

    }

    protected int sourcePort;
    protected int destinationPort;
    protected short length;
    protected short checksum;

    /**
     * @return the sourcePort
     */
    public int getSourcePort() {
        return this.sourcePort;
    }

    /**
     * @param sourcePort
     *            the sourcePort to set
     * @return this
     */
    public UDP setSourcePort(final int sourcePort) {
        this.sourcePort = sourcePort & MASK;
        return this;
    }

    /**
     * @return the destinationPort
     */
    public int getDestinationPort() {
        return this.destinationPort;
    }

    /**
     * @param destinationPort
     *            the destinationPort to set
     * @return this
     */
    public UDP setDestinationPort(final int destinationPort) {
        this.destinationPort = destinationPort & MASK;
        return this;
    }

    /**
     * @return the length
     */
    public short getLength() {
        return this.length;
    }

    /**
     * @return the checksum
     */
    public short getChecksum() {
        return this.checksum;
    }

    /**
     * @param checksum
     *            the checksum to set
     * @return this
     */
    public UDP setChecksum(final short checksum) {
        this.checksum = checksum;
        return this;
    }

    @Override
    public void resetChecksum() {
        this.checksum = 0;
        super.resetChecksum();
    }

    /**
     * Serializes the packet. Will compute and set the following fields if they
     * are set to specific values at the time serialize is called: -checksum : 0
     * -length : 0
     */
    @Override
    public byte[] serialize() {
        byte[] payloadData = null;
        if (this.payload != null) {
            this.payload.setParent(this);
            payloadData = this.payload.serialize();
        }

        this.length = (short) (8 + (payloadData == null ? 0
                : payloadData.length));

        final byte[] data = new byte[this.length];
        final ByteBuffer bb = ByteBuffer.wrap(data);

        byte[] sourcePortBytes = new byte[2];
        byte[] destinationPortBytes = new byte[2];

        sourcePortBytes[0] = (byte) ((this.sourcePort >> 8) & 0xff);
        sourcePortBytes[1] = (byte) (this.sourcePort & 0xff);
        destinationPortBytes[0] = (byte) ((this.destinationPort >> 8) & 0xff);
        destinationPortBytes[1] = (byte) (this.destinationPort & 0xff);

        //bb.putShort((short) this.sourcePort);         // FIXME
        //bb.putShort((short) this.destinationPort);    // FIXME
        bb.put(sourcePortBytes);
        bb.put(destinationPortBytes);

        bb.putShort(this.length);
        bb.putShort(this.checksum);
        if (payloadData != null) {
            bb.put(payloadData);
        }

        if (this.parent != null && this.parent instanceof IPv4) {
            ((IPv4) this.parent).setProtocol(IPv4.PROTOCOL_UDP);
        }

        // compute checksum if needed
        if (this.checksum == 0) {
            bb.rewind();
            int accumulation = 0;

            // compute pseudo header mac
            if (this.parent != null) {
                if (this.parent instanceof IPv4) {
                    final IPv4 ipv4 = (IPv4) this.parent;
                    accumulation += (ipv4.getSourceAddress() >> 16 & 0xffff)
                            + (ipv4.getSourceAddress() & 0xffff);
                    accumulation += (ipv4.getDestinationAddress() >> 16 & 0xffff)
                            + (ipv4.getDestinationAddress() & 0xffff);
                    accumulation += ipv4.getProtocol() & 0xff;
                    accumulation += length & 0xffff;
                } else if (this.parent instanceof IPv6) {
                    final IPv6 ipv6 = (IPv6) this.parent;
                    final int bbLength =
                            Ip6Address.BYTE_LENGTH * 2 // IPv6 src, dst
                                    + 2  // nextHeader (with padding)
                                    + 4; // length
                    final ByteBuffer bbChecksum = ByteBuffer.allocate(bbLength);
                    bbChecksum.put(ipv6.getSourceAddress());
                    bbChecksum.put(ipv6.getDestinationAddress());
                    bbChecksum.put((byte) 0); // padding
                    bbChecksum.put(ipv6.getNextHeader());
                    bbChecksum.putInt(length);
                    bbChecksum.rewind();
                    for (int i = 0; i < bbLength / 2; ++i) {
                        accumulation += 0xffff & bbChecksum.getShort();
                    }
                }
            }

            for (int i = 0; i < this.length / 2; ++i) {
                accumulation += 0xffff & bb.getShort();
            }
            // pad to an even number of shorts
            if (this.length % 2 > 0) {
                accumulation += (bb.get() & 0xff) << 8;
            }

            accumulation = (accumulation >> 16 & 0xffff)
                    + (accumulation & 0xffff);
            this.checksum = (short) (~accumulation & 0xffff);
            bb.putShort(6, this.checksum);
        }
        return data;
    }

    @Override
    public IPacket deserialize(final byte[] data, final int offset,
                               final int length) {

        byte[] sourcePortBytes = new byte[2];
        byte[] destinationPortBytes = new byte[2];

        final ByteBuffer bb = ByteBuffer.wrap(data, offset, length);

        bb.get(sourcePortBytes);
        bb.get(destinationPortBytes);
        this.sourcePort = (new BigInteger(sourcePortBytes).intValue()) & MASK;
        this.destinationPort = (new BigInteger(destinationPortBytes).intValue()) & MASK;
        //this.sourcePort = bb.getShort();
        //this.destinationPort = bb.getShort();
        this.length = bb.getShort();
        this.checksum = bb.getShort();

        Deserializer<? extends IPacket> deserializer;
        if (UDP.PORT_DESERIALIZER_MAP.containsKey(this.destinationPort)) {
            deserializer = UDP.PORT_DESERIALIZER_MAP.get(this.destinationPort);
        } else if (UDP.PORT_DESERIALIZER_MAP.containsKey(this.sourcePort)) {
            deserializer = UDP.PORT_DESERIALIZER_MAP.get(this.sourcePort);
        } else {
            deserializer = Data.deserializer();
        }

        try {
            this.payload = deserializer.deserialize(data, bb.position(),
                                                   bb.limit() - bb.position());
            this.payload.setParent(this);
        } catch (DeserializationException e) {
            return this;
        }
        return this;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 5807;
        int result = super.hashCode();
        result = prime * result + this.checksum;
        result = prime * result + this.destinationPort;
        result = prime * result + this.length;
        result = prime * result + this.sourcePort;
        return result;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (!(obj instanceof UDP)) {
            return false;
        }
        final UDP other = (UDP) obj;
        if (this.checksum != other.checksum) {
            return false;
        }
        if (this.destinationPort != other.destinationPort) {
            return false;
        }
        if (this.length != other.length) {
            return false;
        }
        if (this.sourcePort != other.sourcePort) {
            return false;
        }
        return true;
    }

    /**
     * Deserializer function for UDP packets.
     *
     * @return deserializer function
     */
    public static Deserializer<UDP> deserializer() {
        return (data, offset, length) -> {
            checkInput(data, offset, length, UDP_HEADER_LENGTH);

            byte[] sourcePortBytes = new byte[2];
            byte[] destinationPortBytes = new byte[2];

            UDP udp = new UDP();

            ByteBuffer bb = ByteBuffer.wrap(data, offset, length);

            bb.get(sourcePortBytes);
            bb.get(destinationPortBytes);
            udp.sourcePort = (new BigInteger(sourcePortBytes).intValue()) & MASK;
            udp.destinationPort = (new BigInteger(destinationPortBytes).intValue()) & MASK;

//            udp.sourcePort = bb.getShort();
//            udp.destinationPort = bb.getShort();
            udp.length = bb.getShort();
            udp.checksum = bb.getShort();

            Deserializer<? extends IPacket> deserializer;
            if (UDP.PORT_DESERIALIZER_MAP.containsKey(udp.destinationPort)) {
                deserializer = UDP.PORT_DESERIALIZER_MAP.get(udp.destinationPort);
            } else if (UDP.PORT_DESERIALIZER_MAP.containsKey(udp.sourcePort)) {
                deserializer = UDP.PORT_DESERIALIZER_MAP.get(udp.sourcePort);
            } else {
                deserializer = Data.deserializer();
            }

            udp.payload = deserializer.deserialize(data, bb.position(),
                                                   bb.limit() - bb.position());
            udp.payload.setParent(udp);
            return udp;
        };
    }
}
