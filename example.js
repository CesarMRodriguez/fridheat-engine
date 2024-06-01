//0x746db721c4


var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});

var findings = []; 

findings.length = 0;
ranges.forEach(range => {
    console.log("Searching in " + range);
    Memory.scan(range.base, range.size, '02 00 00 00', {
        onMatch: function(address, size){
            findings.push(address);
        }, 
        onError: function(reason){
                console.log('[!] There was an error scanning memory');
        } 
        });
});



Memory.scan(ranges[0].base, ranges[0].size, '02 00 00 00', {
    onMatch: function(address, size){
            console.log('[+] Pattern found at: ' + address.toString());
        }, 
    onError: function(reason){
            console.log('[!] There was an error scanning memory');
        }, 
    onComplete: function(){
            console.log('[+] Finished');
        }
    });