"""Bounded classic PCAP Ethernet/IPv4/TCP/UDP decoder; rejects unsupported formats."""
import socket
import struct

def packets(path,max_packets=250000):
    with open(path,'rb') as f:
        header=f.read(24)
        if len(header)!=24:raise ValueError('Truncated PCAP header')
        formats={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
        if header[:4] not in formats:raise ValueError('Use classic .pcap; convert PCAPNG first')
        endian,unit=formats[header[:4]]
        major,minor,_,_,snaplen,linktype=struct.unpack(endian+'HHIIII',header[4:])
        if major!=2 or minor!=4 or linktype not in (1,101):raise ValueError('Supported PCAP: v2.4 Ethernet or raw IPv4')
        count=0
        while True:
            record=f.read(16)
            if not record:break
            if len(record)!=16:raise ValueError('Truncated packet record')
            sec,sub,captured,original=struct.unpack(endian+'IIII',record)
            if captured>262144 or captured>snaplen or captured>original:raise ValueError('Invalid capture length')
            data=f.read(captured)
            if len(data)!=captured:raise ValueError('Truncated packet bytes')
            count+=1
            if count>max_packets:raise ValueError('Packet count limit exceeded')
            offset=0
            if linktype==1:
                if len(data)<14:raise ValueError('Truncated Ethernet frame')
                kind=struct.unpack('!H',data[12:14])[0];offset=14
                for _ in range(2):
                    if kind in (0x8100,0x88a8):
                        if len(data)<offset+4:raise ValueError('Truncated VLAN header')
                        kind=struct.unpack('!H',data[offset+2:offset+4])[0];offset+=4
                if kind!=0x0800:continue
            ip=data[offset:]
            if len(ip)<20 or ip[0]>>4!=4:continue
            ihl=(ip[0]&15)*4;length=struct.unpack('!H',ip[2:4])[0]
            if ihl<20 or length<ihl or len(ip)<length:raise ValueError('Truncated IPv4 packet; use full-snaplen capture')
            frag=struct.unpack('!H',ip[6:8])[0];proto=ip[9]
            item=dict(t=sec+sub/unit,src=socket.inet_ntoa(ip[12:16]),dst=socket.inet_ntoa(ip[16:20]),bytes=original,ttl=ip[8],frag=bool(frag&0x3fff),protocol='other',sport=0,dport=0,flags=0,win=0,seq=None,payload_len=0)
            if frag&0x1fff:yield item;continue
            transport=ip[ihl:length]
            if proto==6:
                if len(transport)<20:raise ValueError('Truncated TCP header')
                tcp_len=(transport[12]>>4)*4
                if tcp_len<20 or tcp_len>len(transport):raise ValueError('Invalid TCP data offset')
                sport,dport,seq=struct.unpack('!HHI',transport[:8])
                item.update(protocol='tcp',sport=sport,dport=dport,seq=seq,flags=transport[13],win=struct.unpack('!H',transport[14:16])[0],payload_len=len(transport)-tcp_len)
            elif proto==17:
                if len(transport)<8:raise ValueError('Truncated UDP header')
                sport,dport=struct.unpack('!HH',transport[:4]);item.update(protocol='udp',sport=sport,dport=dport)
            yield item
