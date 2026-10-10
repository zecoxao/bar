"""Full PS4 seg3 registry codec (decode + ENCODE), verified against real backups.
All transforms reversed from 1352k.elf sub_826E6690 / 505k.elf sub_826F44A0 (identical)."""
import struct, sys
from Crypto.Cipher import AES

KEY_NEW = bytes.fromhex("101851B22B669178970C5459B3CB8D45")
KEY_OLD = bytes.fromhex("79C8CCC889A1540D4F2E27BB614FD653")
OBF_T  = bytes.fromhex("418985638cc3972fd88d9ce6d7e1d5308a84a534b844754ef341c557fa2bd0")  # 31B
KID_T  = bytes.fromhex("1f26fd8dbf0a8d927f6ba012b40e8fb1")   # 16B
HASH_S = bytes.fromhex("72028561e01cbb89")                   # 8B
T3     = bytes.fromhex("2358b7ac942494b9")                   # header XOR key (8B)

def cbc_dec(KEY, iv, ct):
    n=len(ct); full=n-(n%16); out=bytearray()
    if full: out+=AES.new(KEY,AES.MODE_CBC,iv).decrypt(ct[:full])
    r=n-full
    if r:
        prev=ct[full-16:full] if full>=16 else iv
        ks=AES.new(KEY,AES.MODE_ECB).encrypt(prev); out+=bytes(ct[full+i]^ks[i] for i in range(r))
    return bytes(out)

def get_seg(path, idx):
    data=open(path,"rb").read()
    e=data[48+64*idx:48+64*idx+64]
    off=struct.unpack("<Q",e[8:16])[0]; nop=struct.unpack("<Q",e[56:64])[0]; seed=e[40:56]
    e0=data[48:112]; o0=struct.unpack("<Q",e0[8:16])[0]; n0=struct.unpack("<Q",e0[56:64])[0]; s0=e0[40:56]
    KEY=next(k for k in (KEY_NEW,KEY_OLD) if cbc_dec(k,s0,data[o0:o0+n0])[:4]==b"P4BR")
    return cbc_dec(KEY,seed,data[off:off+nop])

def obf(buf, key):                       # sub_826F4B10 (self-inverse XOR)
    buf=bytearray(buf); ln=len(buf)
    v3=(17*ln+((17*((key&0xffffffff)+((key>>16)&0xffff)))&0xffff))&0xffffffffffffffff
    v5=v3%7; m=((32-3*v5)&0xFFFFFFFE)-1
    for i in range(ln): buf[i]^=OBF_T[v5+(i%m)]
    return bytes(buf)

def chk(data, outlen):                   # sub_826F4BC0
    acc=int.from_bytes(HASH_S,"little"); ln=len(data); v8=0; v9=0
    while True:
        v9=v8
        if v8<ln:
            v10=acc; sh=0; k=0
            while True:
                b=data[v9]
                v10=(v10+(((b^HASH_S[k])&0xff)<<sh))&0xffffffffffffffff
                v10=(v10*(3 if b==0 else b))&0xffffffffffffffff
                last=k+1; v9=v8+k+1
                if v9>=ln: break
                sh+=8
                if not (k<7): break
                k+=1
            v8+=last; acc=v10
        if v9>=ln: break
    ab=acc.to_bytes(8,"little")
    return bytes(ab[7-i] for i in range(outlen))

def roundblk(size): return 0 if size==0 else ((size+7)&0xFFFFFFFC)
def kid_mask(v138):                      # desc+0 encode (== decode, XOR)
    v63=v138%13
    b=[(v138>>24)&0xff,(v138>>16)&0xff,(v138>>8)&0xff,v138&0xff]
    d=[b[j]^KID_T[v63+j] for j in range(4)]
    return struct.pack("<I",(d[0]<<24)|(d[1]<<16)|(d[2]<<8)|d[3]), v63
def dexor_hdr(seg3): return bytes(seg3[i]^T3[i%8] for i in range(80))

# ---------------- DECODE ----------------
def decode(seg3):
    hdr=bytearray(dexor_hdr(seg3))
    total=struct.unpack("<H",hdr[4:6])[0]
    entries=[]            # active, in order: dict(v138,type,size,value|inline)
    data_start=0x50+16*total
    for i in range(total):
        d=bytearray(obf(seg3[0x50+16*i:0x50+16*i+16], i))
        if bytes(d)==b"\x17"*16: continue       # inactive filler
        v57=struct.unpack("<H",d[8:10])[0]
        typ=struct.unpack("<H",d[4:6])[0]; size=struct.unpack("<H",d[6:8])[0]
        off=struct.unpack("<I",d[12:16])[0]
        enc=struct.unpack("<I",d[0:4])[0]
        # recover v138 via XOR with KID at v57
        b=[(enc>>24)&0xff,(enc>>16)&0xff,(enc>>8)&0xff,enc&0xff]
        dd=[b[j]^KID_T[v57+j] for j in range(4)]
        v138=(dd[0]<<24)|(dd[1]<<16)|(dd[2]<<8)|dd[3]
        if typ==0:
            entries.append(dict(v138=v138,type=typ,size=size,inline=off,value=None))
        else:
            blk=obf(seg3[data_start+off:data_start+off+roundblk(size)], v138)
            entries.append(dict(v138=v138,type=typ,size=size,inline=None,value=blk[4:4+size]))
    return dict(hdr=hdr,total=total,entries=entries)

# ---------------- ENCODE ----------------
def encode(total, entries, hdr_src, blob_size=0x64600):
    buf=bytearray(blob_size)
    emitted=len(entries)
    v45=0x50+16*total                     # index-table end / data-area start
    # ---- index descriptors (active, contiguous slots 0..emitted-1) ----
    datalen=0
    for i,e in enumerate(entries):
        desc=bytearray(16)
        km,v63=kid_mask(e["v138"]); desc[0:4]=km
        struct.pack_into("<H",desc,4,e["type"])
        struct.pack_into("<H",desc,6,e["size"])
        struct.pack_into("<H",desc,8,v63)
        if e["type"]==0:
            struct.pack_into("<I",desc,12,e["inline"])
        else:
            struct.pack_into("<I",desc,12,datalen)
            blen=roundblk(e["size"])
            block=bytearray(b"\x22"*blen)
            block[0:4]=chk(e["value"],4)            # data checksum over value
            block[4:4+e["size"]]=e["value"]
            buf[v45+datalen:v45+datalen+blen]=obf(block, e["v138"])
            datalen+=blen
        struct.pack_into("<H",desc,10,struct.unpack("<H",chk(bytes(desc),2))[0])  # desc chk (+10)
        buf[0x50+16*i:0x50+16*i+16]=obf(bytes(desc), i)
    # ---- inactive filler slots emitted..total-1 ----
    for i in range(emitted,total):
        buf[0x50+16*i:0x50+16*i+16]=obf(b"\x17"*16, i)
    # ---- trailing padding: 0xE5 then obf in 0xE9 chunks ----
    pstart=v45+datalen
    for j in range(pstart, blob_size): buf[j]=0xE5
    off=0; rem=blob_size-pstart; base=pstart
    while rem>0:
        clen=233 if rem>0xE8 else rem
        buf[base+off:base+off+clen]=obf(bytes(buf[base+off:base+off+clen]), off)
        off+=clen; rem-=clen
    # ---- header (copy opaque status bytes from source plaintext, recompute derived) ----
    h=bytearray(80)
    h[0:4]   = hdr_src[0:4]        # id/version
    struct.pack_into("<H",h,4,total)
    struct.pack_into("<H",h,6,emitted)
    struct.pack_into("<I",h,8,datalen)
    h[16:32] = hdr_src[16:32]      # OpenPSID
    h[32:36] = hdr_src[32:36]      # reg 0x1060000 value
    h[40:47] = hdr_src[40:47]      # +0x28..+0x2E status
    h[56]    = hdr_src[56]         # +0x38
    struct.pack_into("<H",h,36,struct.unpack("<H",chk(bytes(h[32:36]),2))[0])  # +0x24
    v151=bytes([h[0x2B],h[0x2A],h[0x29],h[0x28]])
    struct.pack_into("<H",h,38,struct.unpack("<H",chk(v151,2))[0])             # +0x26
    struct.pack_into("<I",h,12,struct.unpack("<I",chk(bytes(h),4))[0])         # +0x0C hdr chk (after all else, +0x0C=0)
    buf[0:80]=bytes(h[i]^T3[i%8] for i in range(80))
    return bytes(buf)

if __name__=="__main__":
    sys.stdout.reconfigure(encoding="utf-8",errors="replace")
    path=sys.argv[1]
    orig=get_seg(path,3)
    dec=decode(orig)
    re=encode(dec["total"], dec["entries"], dec["hdr"], blob_size=len(orig))
    print(f"seg3 len={len(orig):#x} total={dec['total']} active={len(dec['entries'])}")
    if re==orig:
        print("ROUND-TRIP: BYTE-IDENTICAL  ✓ (encoder reproduces the exact blob)")
    else:
        diff=[i for i in range(len(orig)) if re[i]!=orig[i]]
        print(f"ROUND-TRIP: {len(diff)} bytes differ; first at {diff[0]:#x}")
        for i in diff[:8]:
            print(f"  @{i:#x} orig={orig[i]:#04x} re={re[i]:#04x}")
