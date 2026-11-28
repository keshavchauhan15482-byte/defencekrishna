/** Read only archived metadata; never export tokens, variants or raw memory. */
export function archiveCounts(raw){
 const rows=JSON.parse(raw).learnedPatterns;
 if(!Array.isArray(rows))throw Error("Invalid archive");
 const patterns=rows.length;
 let generated=0,reported=0;
 for(const row of rows){
  const n=row?.syntheticMutationsCount;
  if(Number.isSafeInteger(n)&&n>=0&&n<=1000000){generated+=n;reported++;}
 }
 if(!Number.isSafeInteger(generated))throw Error("Invalid archived count");
 return {patterns,generated,reported};
}
