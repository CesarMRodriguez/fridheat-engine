import { MemoryPage, MemoryPages } from "./process.js"

class MemorySearch {

    protected findings: NativePointer[] = [];

    public find_first(value: any, memoryPages: MemoryPages) {

        console.log("finding first coincidences with: " + value);
        this.findings.length = 0;
        let memory_pages: MemoryPage[] = memoryPages.getValidPages()

        let str_condition = this.getHexaRepresentation(value)

        memory_pages.forEach(memory_page => {
            Memory.scan(memory_page.getBase(), memory_page.getSize(), str_condition, {
                onMatch: (address, size) => {
                    this.findings.push(address)
                },
                onError: (reason) => {
                    console.log('[!] There was an error scanning memory' + reason)
                }
            });
        });
    }

    getHexaRepresentation(value: any): string {
        return value + ""
    }

    public readValue(address: NativePointer): any {
        return address.readByteArray(4)
    }

    public filter_findings_by_exact_value(value: any) {
        this.findings = this.findings.filter(finding => {
            return finding.readByteArray(4) == value
        })
    }

    public writeValue(address: NativePointer, value: any) {
        address.writeByteArray(value)
    }
}

class IntMemorySearch extends MemorySearch {

    getHexaRepresentation(value: any): string {
        let intValue = Number(value);

        if (isNaN(intValue)) {
            throw new Error("Invalid number value");
        }

        // Convert the number to a hexadecimal string
        let hexaString = intValue.toString(16);

        // Ensure the string has an even number of characters
        if (hexaString.length % 2 !== 0) {
            hexaString = '0' + hexaString;
        }

        // Split the string into bytes
        let bytes = hexaString.match(/.{1,2}/g);

        if (bytes === null) {
            throw new Error("Failed to split the hex string into bytes");
        }

        // Reverse the byte order to achieve little-endian format
        let reversedBytes = bytes.reverse();

        // Pad the bytes to ensure we have 4 bytes (8 hex characters)
        while (reversedBytes.length < 4) {
            reversedBytes.push("00");
        }

        // Join the bytes with spaces
        let littleEndianHexString = reversedBytes.join(" ");

        return littleEndianHexString.toUpperCase();
    }

    public readValue(address: NativePointer): any {
        return address.readInt()
    }

    public filter_findings_by_exact_value(value: any) {
        this.findings = this.findings.filter(finding => {
            let intValue = Number(value);
            if (isNaN(intValue)) {
                return false;
            }
            return finding.readInt() == intValue
        })
    }

    public writeValue(address: NativePointer, value: any) {
        let intValue = Number(value);
        address.writeInt(intValue)
    }
}