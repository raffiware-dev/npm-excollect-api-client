import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc.js';
import timezone from 'dayjs/plugin/timezone.js'; 
import { Buffer } from 'buffer';

dayjs.extend(utc);
dayjs.extend(timezone);

// var a = dayjs.duration(1, 'd');
// var b = dayjs.duration(2, 'd');
// 
// a.add(b).days(); // 3
// a.add({ days: 2 } ).days();
// a.add(2, 'days');

export function getCurrentTimeStamp() {
  return getTimeStamp(getCurrentTime());
} 

export function getCurrentTime() {

  return dayjs().tz('utc');
}  

export function getTimeStamp( day: dayjs.Dayjs ) {

  // ISO 8601 with fractional seconds and time zone offset.
  return day.format('YYYY-MM-DDTHH:mm:ss.SSSZ'); 
} 

export function idToUuid ( id: string ) {
   return uuidBufToUuid( idToUuidBuf(id) )
}

export function uuidToId ( idType: string, uuid: string ) {
  return  idType +'_'+ uuid.replaceAll("-", "").toLowerCase(); 
}

export function idToUuidBuf( 
   id: string
) {
  const idHex = id.substring( id.indexOf('_') + 1 );

  return new Uint8Array(hex2buf(idHex));
}

export function uuidBufToUuid( 
   uuidBuf: Uint8Array 
) {

  const hexVals = Array.from(uuidBuf.slice(0,16))
                       .map( h => { return h.toString(16).padStart(2, '0')} );

  const hexSlicer = function(s: number ,d: number ) { return hexVals.slice(s,d).join("") }

  return `${hexSlicer(0,4)}-${hexSlicer(4,6)}-${hexSlicer(6,8)}-${hexSlicer(8,10)}-${hexSlicer(10,16)}` 
}

function hex2buf( 
  str: string 
) {
  return Buffer.from(str, 'hex') 
}