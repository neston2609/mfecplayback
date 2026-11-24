import { inflateRawSync } from 'node:zlib';

const MAX_ARCHIVE_BYTES=128*1024*1024;
const MAX_TRACK_BYTES=256*1024*1024;
const MAX_TRACKS=16;

export type ScreenTrack={id:string;name:string;bytes:Buffer;mimeType:'video/webm'};

/** Safely extracts monitor WebM files from a Genesys screen-recording ZIP without writing ZIP paths to disk. */
export function extractScreenTracksFromZip(archive:Buffer):ScreenTrack[]{
  if(archive.length<22||archive.length>MAX_ARCHIVE_BYTES)throw new Error('Screen recording ZIP is empty, malformed, or exceeds the 128 MB playback limit.');
  const eocd=findEndOfCentralDirectory(archive),disk=archive.readUInt16LE(eocd+4),centralDisk=archive.readUInt16LE(eocd+6),entriesOnDisk=archive.readUInt16LE(eocd+8),entryCount=archive.readUInt16LE(eocd+10),centralSize=archive.readUInt32LE(eocd+12),centralOffset=archive.readUInt32LE(eocd+16),commentLength=archive.readUInt16LE(eocd+20);
  if(disk!==0||centralDisk!==0||entriesOnDisk!==entryCount||entryCount===0||entryCount>100||eocd+22+commentLength!==archive.length||centralOffset+centralSize>eocd)throw new Error('Screen recording ZIP has an unsupported or malformed directory.');
  let cursor=centralOffset,totalSize=0;const tracks:ScreenTrack[]=[];
  for(let index=0;index<entryCount;index++){
    if(cursor+46>archive.length||archive.readUInt32LE(cursor)!==0x02014b50)throw new Error('Screen recording ZIP has a malformed file entry.');
    const madeBy=archive.readUInt16LE(cursor+4)>>>8,flags=archive.readUInt16LE(cursor+8),method=archive.readUInt16LE(cursor+10),crc=archive.readUInt32LE(cursor+16),compressedSize=archive.readUInt32LE(cursor+20),size=archive.readUInt32LE(cursor+24),nameLength=archive.readUInt16LE(cursor+28),extraLength=archive.readUInt16LE(cursor+30),entryCommentLength=archive.readUInt16LE(cursor+32),diskStart=archive.readUInt16LE(cursor+34),externalAttributes=archive.readUInt32LE(cursor+38),localOffset=archive.readUInt32LE(cursor+42),entryEnd=cursor+46+nameLength+extraLength+entryCommentLength;
    if(entryEnd>archive.length||diskStart!==0||compressedSize===0xffffffff||size===0xffffffff||localOffset===0xffffffff)throw new Error('Screen recording ZIP uses unsupported ZIP64 or split-file features.');
    const nameBytes=archive.subarray(cursor+46,cursor+46+nameLength),name=nameBytes.toString(flags&0x800?'utf8':'latin1'),directory=name.endsWith('/');
    if(!name||name.includes('\0')||name.includes('\\')||name.startsWith('/')||name.split('/').some(part=>part==='.'||part==='..'))throw new Error('Screen recording ZIP contains an unsafe file name.');
    if((flags&0x2041)!==0||(method!==0&&method!==8))throw new Error('Screen recording ZIP uses encryption or an unsupported compression method.');
    const unixMode=externalAttributes>>>16,fileType=madeBy===3?unixMode&0xf000:0;if(fileType&&fileType!==0x8000&&fileType!==0x4000)throw new Error('Screen recording ZIP contains a non-regular file.');
    if(!directory&&/\.webm$/i.test(name)){
      if(tracks.length>=MAX_TRACKS||!size||size>MAX_TRACK_BYTES||compressedSize>MAX_ARCHIVE_BYTES||size>Math.max(compressedSize*1000,1024*1024))throw new Error('Screen recording ZIP has too many, too large, or suspiciously compressed monitor videos.');
      totalSize+=size;if(totalSize>MAX_TRACK_BYTES)throw new Error('Combined monitor videos exceed the 256 MB playback limit.');
      const local=localOffset;if(local+30>archive.length||archive.readUInt32LE(local)!==0x04034b50)throw new Error('Screen recording ZIP has a malformed local file header.');
      const localFlags=archive.readUInt16LE(local+6),localMethod=archive.readUInt16LE(local+8),localNameLength=archive.readUInt16LE(local+26),localExtraLength=archive.readUInt16LE(local+28),dataOffset=local+30+localNameLength+localExtraLength;
      if(localFlags!==flags||localMethod!==method||dataOffset+compressedSize>centralOffset||!archive.subarray(local+30,local+30+localNameLength).equals(nameBytes))throw new Error('Screen recording ZIP local and central headers do not match.');
      if(!(flags&0x08)&&(archive.readUInt32LE(local+14)!==crc||archive.readUInt32LE(local+18)!==compressedSize||archive.readUInt32LE(local+22)!==size))throw new Error('Screen recording ZIP local and central sizes do not match.');
      let bytes:Buffer;try{const compressed=archive.subarray(dataOffset,dataOffset+compressedSize);bytes=method===0?Buffer.from(compressed):inflateRawSync(compressed,{maxOutputLength:MAX_TRACK_BYTES});}catch{throw new Error('Screen recording ZIP monitor video could not be decompressed safely.');}
      if(bytes.length!==size||crc32(bytes)!==crc||bytes.length<4||!bytes.subarray(0,4).equals(Buffer.from([0x1a,0x45,0xdf,0xa3])))throw new Error('Screen recording ZIP contains a monitor file that failed WebM or integrity validation.');
      tracks.push({id:String(tracks.length),name:name.split('/').pop()||`Monitor ${tracks.length+1}.webm`,bytes,mimeType:'video/webm'});
    }
    cursor=entryEnd;
  }
  if(cursor!==centralOffset+centralSize||!tracks.length)throw new Error('Screen recording ZIP does not contain supported WebM monitor video.');
  return tracks;
}

export function screenTrackFromWebm(bytes:Buffer,name='Screen recording.webm'):ScreenTrack{
  if(!bytes.length||bytes.length>MAX_TRACK_BYTES||bytes.length<4||!bytes.subarray(0,4).equals(Buffer.from([0x1a,0x45,0xdf,0xa3])))throw new Error('Screen recording is not a supported WebM video or exceeds the 256 MB playback limit.');
  return {id:'0',name:name.replace(/[\\/\0]/g,'_').slice(0,180),bytes,mimeType:'video/webm'};
}

function findEndOfCentralDirectory(archive:Buffer){const minimum=Math.max(0,archive.length-22-0xffff);for(let offset=archive.length-22;offset>=minimum;offset--)if(archive.readUInt32LE(offset)===0x06054b50)return offset;throw new Error('Screen recording response is not a valid ZIP archive.');}
const crcTable=(()=>{const table=new Uint32Array(256);for(let n=0;n<256;n++){let value=n;for(let bit=0;bit<8;bit++)value=value&1?0xedb88320^(value>>>1):value>>>1;table[n]=value>>>0;}return table;})();
function crc32(data:Buffer){let value=0xffffffff;for(const byte of data)value=crcTable[(value^byte)&0xff]^(value>>>8);return(value^0xffffffff)>>>0;}
