📦
519 /agent/index.js.map
415 /agent/index.js
2101 /agent/process.js.map
2152 /agent/process.js
✄
{"version":3,"file":"index.js","sourceRoot":"C:/Users/lucho/Documents/fridheat-engine/core2/","sources":["agent/index.ts"],"names":[],"mappings":"AAAA,OAAO,EAAc,WAAW,EAAE,MAAM,cAAc,CAAA;AACtD,OAAO,CAAC,GAAG,CAAC,kBAAkB,CAAC,CAAA;AAC/B;;;;;EAKE;AAEF,IAAI,WAAW,GAAG,IAAI,WAAW,EAAE,CAAA;AACnC,WAAW,CAAC,gBAAgB,CAAC,qBAAqB,CAAC,CAAA;AACnD,MAAM,gBAAgB,GAAiB,WAAW,CAAC,aAAa,EAAE,CAAA;AAClE,gBAAgB,CAAC,OAAO,CAAC,CAAC,UAAU,EAAE,EAAE;IACpC,UAAU,CAAC,aAAa,EAAE,CAAA;AAC9B,CAAC,CAAC,CAAA;AAEF,OAAO,CAAC,GAAG,CAAC,WAAW,CAAC,CAAA"}
✄
import { MemoryPages } from "./process.js";
console.log("printing results");
/*
No test now
memoryPages.forEach((memoryPage) => {
    memoryPage.displayConfig()
})
*/
let memoryPages = new MemoryPages();
memoryPages.filterByFilename("mynativeapplication");
const validMemoryPages = memoryPages.getValidPages();
validMemoryPages.forEach((memoryPage) => {
    memoryPage.displayConfig();
});
console.log("termino 5");
✄
{"version":3,"file":"process.js","sourceRoot":"C:/Users/lucho/Documents/fridheat-engine/core2/","sources":["agent/process.ts"],"names":[],"mappings":"AAAA,MAAM,OAAO,UAAU;IAInB,YAAY,YAA0B,EAAE,SAAkB;QACtD,IAAI,CAAC,YAAY,GAAG,YAAY,CAAC;QACjC,IAAI,CAAC,OAAO,GAAG,SAAS,CAAC;IAC7B,CAAC;IAED,wCAAwC;IACjC,aAAa;QAChB,IAAI,CAAC,OAAO,GAAG,CAAC,IAAI,CAAC,OAAO,CAAC;IACjC,CAAC;IAEM,UAAU,CAAC,OAAgB;QAC9B,IAAI,CAAC,OAAO,GAAG,OAAO,CAAA;IAC1B,CAAC;IAEM,SAAS;QACZ,OAAO,IAAI,CAAC,OAAO,CAAA;IACvB,CAAC;IACM,WAAW;QACd,IAAI,SAAS,GAAG,EAAE,CAAA;QAClB,IAAI,IAAI,CAAC,YAAY,CAAC,IAAI,EAAE,IAAI,EAAE;YAC9B,SAAS,GAAG,IAAI,CAAC,YAAY,CAAC,IAAI,CAAC,IAAI,CAAC;SAC3C;QACD,OAAO,SAAS,CAAA;IACpB,CAAC;IAEM,OAAO;QACV,OAAO,IAAI,CAAC,YAAY,CAAC,IAAI,CAAA;IACjC,CAAC;IAED,8CAA8C;IAC9C,aAAa;QAET,OAAO,CAAC,GAAG,CAAC,WAAW,IAAI,CAAC,WAAW,EAAE,MAAM,IAAI,CAAC,YAAY,CAAC,IAAI,MAAM,IAAI,CAAC,YAAY,CAAC,IAAI,MAAM,IAAI,CAAC,YAAY,CAAC,UAAU,eAAe,IAAI,CAAC,OAAO,EAAE,CAAC,CAAC;IACtK,CAAC;CACJ;AAED,MAAM,OAAO,WAAW;IAIpB;QAFQ,gBAAW,GAAiB,EAAE,CAAA;QAGlC,IAAI,MAAM,GAAmB,OAAO,CAAC,eAAe,CAAC,KAAK,CAAC,CAAA;QAE3D,MAAM,CAAC,OAAO,CAAC,CAAC,KAAK,EAAE,EAAE;YACrB,IAAI,CAAC,WAAW,CAAC,IAAI,CAAC,IAAI,UAAU,CAAC,KAAK,EAAE,IAAI,CAAC,CAAC,CAAA;QACtD,CAAC,CAAC,CAAA;IACN,CAAC;IAED,4CAA4C;IACrC,gBAAgB,CAAC,SAAiB;QAErC,IAAI,CAAC,WAAW,CAAC,OAAO,CAAC,CAAC,UAAU,EAAE,EAAE;YACpC,4CAA4C;YAC5C,UAAU,CAAC,UAAU,CAAC,UAAU,CAAC,WAAW,EAAE,CAAC,QAAQ,CAAC,SAAS,CAAC,CAAC,CAAA;QACvE,CAAC,CAAC,CAAA;IACN,CAAC;IAED,gDAAgD;IACzC,mBAAmB,CAAC,WAAmB,EAAE,UAAkB;QAC9D,MAAM,aAAa,GAAG,QAAQ,CAAC,WAAW,EAAE,EAAE,CAAC,CAAC;QAChD,MAAM,UAAU,GAAG,QAAQ,CAAC,UAAU,EAAE,EAAE,CAAC,CAAC;QAE5C,IAAI,CAAC,WAAW,CAAC,OAAO,CAAC,CAAC,UAAU,EAAE,EAAE;YACpC,MAAM,WAAW,GAAG,QAAQ,CAAC,UAAU,CAAC,OAAO,EAAE,CAAC,QAAQ,EAAE,EAAE,EAAE,CAAC,CAAC;YAClE,UAAU,CAAC,UAAU,CAAC,WAAW,IAAI,aAAa,IAAI,WAAW,IAAI,UAAU,CAAC,CAAA;QACpF,CAAC,CAAC,CAAA;IACN,CAAC;IAEM,aAAa;QAChB,OAAO,IAAI,CAAC,WAAW,CAAC,MAAM,CAAC,UAAU,CAAC,EAAE;YACxC,OAAO,UAAU,CAAC,SAAS,EAAE,CAAC;QAClC,CAAC,CAAC,CAAC;IACP,CAAC;IAEM,qBAAqB;QACxB,IAAI,CAAC,WAAW,CAAC,OAAO,CAAC,CAAC,UAAU,EAAE,EAAE;YACpC,UAAU,CAAC,aAAa,EAAE,CAAA;QAC9B,CAAC,CAAC,CAAA;IACN,CAAC;CACJ"}
✄
export class MemoryPage {
    constructor(rangeDetails, isEnabled) {
        this.rangeDetails = rangeDetails;
        this.enabled = isEnabled;
    }
    // Method to toggle the isEnabled status
    toggleEnabled() {
        this.enabled = !this.enabled;
    }
    setEnabled(enabled) {
        this.enabled = enabled;
    }
    isEnabled() {
        return this.enabled;
    }
    getFileName() {
        let file_path = "";
        if (this.rangeDetails.file?.path) {
            file_path = this.rangeDetails.file.path;
        }
        return file_path;
    }
    getBase() {
        return this.rangeDetails.base;
    }
    // Method to display the configuration details
    displayConfig() {
        console.log(`Range: [${this.getFileName()} - ${this.rangeDetails.base} - ${this.rangeDetails.size} - ${this.rangeDetails.protection}], Enabled: ${this.enabled}`);
    }
}
export class MemoryPages {
    constructor() {
        this.memoryPages = [];
        let ranges = Process.enumerateRanges('r--');
        ranges.forEach((range) => {
            this.memoryPages.push(new MemoryPage(range, true));
        });
    }
    // Method to filter memory pages by filename
    filterByFilename(file_name) {
        this.memoryPages.forEach((memoryPage) => {
            //set the value only if the fileName matches
            memoryPage.setEnabled(memoryPage.getFileName().includes(file_name));
        });
    }
    // Method to filter memory pages by memory range
    filterByMemoryRange(init_memory, end_memory) {
        const inicioDecimal = parseInt(init_memory, 16);
        const finDecimal = parseInt(end_memory, 16);
        this.memoryPages.forEach((memoryPage) => {
            const baseDecimal = parseInt(memoryPage.getBase().toString(), 16);
            memoryPage.setEnabled(baseDecimal >= inicioDecimal && baseDecimal <= finDecimal);
        });
    }
    getValidPages() {
        return this.memoryPages.filter(memoryPage => {
            return memoryPage.isEnabled();
        });
    }
    displayAllMemoryPages() {
        this.memoryPages.forEach((memoryPage) => {
            memoryPage.displayConfig();
        });
    }
}