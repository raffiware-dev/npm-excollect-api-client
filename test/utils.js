import { expect, assert } from "chai";
import dayjs from 'dayjs';
import AxiosMockAdapter from 'axios-mock-adapter'; 

//const utils = require('../dist/excollect-client/utils');
import { 
  getCurrentTimeStamp,
  getCurrentTime,
  getTimeStamp,
  uuidToId
} from '../dist/excollect-client/utils.js';

describe("CurrentTimeStamp", function() { 

   const iso8601_re = /\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d+([+-][0-2]\d:[0-5]\d|Z)/;

   it( 'should assert', function () {

      assert.isDefined( getCurrentTimeStamp()  );

   });
   it( 'should match ISO8601', function () { 
        expect(iso8601_re.test( getCurrentTimeStamp() )).to.be.true;
   }); 

});

describe("CurrentTime", function() { 

   const day = getCurrentTime();

   const nextDay = day.add(1,'year');
   //const a = dayjs()
   //const b = a.add(1, 'day')

   //nextDay.add( dayjs().duration({'days' : 1}) );

   console.log( getTimeStamp(day) );
   console.log( getTimeStamp(nextDay) );

   it( 'should assert', function () {

      assert.isDefined( day );

   });
   it( 'should be UTC ', function () { 
     assert.equal(day.format('Z'), '+00:00');
        //expect();
   }); 

}); 

describe("uuids and ids", function() { 


   it( 'should return id', function () {
     
      const uuid = '46c93015-90fb-4102-ae81-7f3e19c13e34';
      const id   = uuidToId('s', uuid);

      assert.isDefined( id );
      assert.equal(id, 's_46c9301590fb4102ae817f3e19c13e34');
   });

   it( 'should normalize to lower case', function () {
     
      const uuid = '46C93015-90FB-4102-AE81-7F3E19C13E34';
      const id   = uuidToId('s', uuid);

      assert.equal(id, 's_46c9301590fb4102ae817f3e19c13e34');
   });

});