/* flesh this out or by some miracle find a good logging library */
import { getCurrentTimeStamp }  from './utils.js';  

export class Logger {

   // eslint-disable-next-line @typescript-eslint/no-explicit-any
   error( ...msg: any[] ) {
     this.logMsg('error', ...msg)
   } 
   // eslint-disable-next-line @typescript-eslint/no-explicit-any 
   info( msg: any ) {
     this.logMsg('info', msg)
   } 
   // eslint-disable-next-line @typescript-eslint/no-explicit-any  
   debug( ...msg: any[] ) {
     this.logMsg('debug', ...msg)
   }  
   // eslint-disable-next-line @typescript-eslint/no-explicit-any  
   fatal(msg: any ) {
     this.logMsg('fatal', msg)
   } 
   // eslint-disable-next-line @typescript-eslint/no-explicit-any  
   trace(msg: any ) {
     this.logMsg('trace', msg)
   }
   // eslint-disable-next-line @typescript-eslint/no-explicit-any  
   logMsg( level: string, ...msg: any[] ) {
     console.log( getCurrentTimeStamp(), level, msg)
   }

}

const loggerUtils = {
    "getLogger" : function () { return new Logger(); } 
}

export default loggerUtils;  
