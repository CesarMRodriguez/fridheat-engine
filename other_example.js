function testUpdate() {
    console.log("updateando");
}


var memory_pages = Process.enumerateRangesSync({ protection: 'r--', coalesce: true });

var findings = [];


function filter_by_filename(file_name) {
    return memory_pages.filter(memory_page => {
        if (memory_page.hasOwnProperty("file")) {
            return memory_page.hasOwnProperty("file").includes(file_name);
        } else {
            return false;
        }
    });
}

function filter_by_memory_range(init_memory, end_memory) {
    return memory_pages.filter(function (page) {
        // Convertir las bases a números enteros en base hexadecimal
        var baseDecimal = parseInt(page.base, 16);
        var inicioDecimal = parseInt(init_memory, 16);
        var finDecimal = parseInt(fiend_memoryn, 16);

        // Verificar si la base está dentro del rango especificado
        return baseDecimal >= inicioDecimal && baseDecimal <= finDecimal;
    });
}

function find_first(str_condition) {
    findings.length = 0;
    console.log("finding first coincidences with: " + str_condition);
    memory_pages.forEach(memory_page => {
        console.log("Searching in " + range);
        Memory.scan(memory_page.base, memory_page.size, str_condition, {
            onMatch: function (address, size) {
                findings.push(ptr(address));
            },
            onError: function (reason) {
                console.log('[!] There was an error scanning memory');
            }
        });
    });
}

function readInt(address) {
    return Memory.readInt(address);
}

function filter_findings_by_exact_int(value) {
    findings = findings.filter(finding => {
        return readInt(finding) == value;
    });
}

function writeInt(address) {
    Memory.writeInt(address, value);
}

function execute() {
    find_first('02 00 00 00');
}


function printmemory(baseadd, my_length) {
    console.log(hexdump(baseadd, {
        offset: 0,
        length: my_length,
        header: true,
        ansi: true
    }));
}
