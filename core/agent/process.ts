export class MemoryPage {
    private rangeDetails: RangeDetails;
    private enabled: boolean;

    constructor(rangeDetails: RangeDetails, isEnabled: boolean) {
        this.rangeDetails = rangeDetails;
        this.enabled = isEnabled;
    }

    // Method to toggle the isEnabled status
    public toggleEnabled(): void {
        this.enabled = !this.enabled;
    }

    public setEnabled(enabled: boolean): void {
        this.enabled = enabled
    }

    public isEnabled(): boolean {
        return this.enabled
    }
    public getFileName(): string {
        let file_path = ""
        if (this.rangeDetails.file?.path) {
            file_path = this.rangeDetails.file.path;
        }
        return file_path
    }

    public getBase(): NativePointer {
        return this.rangeDetails.base
    }

    getSize(): number {
        return this.rangeDetails.size;
    }

    // Method to display the configuration details
    displayConfig(): void {

        console.log(`Range: [${this.getFileName()} - ${this.rangeDetails.base} - ${this.rangeDetails.size} - ${this.rangeDetails.protection}], Enabled: ${this.enabled}`);
    }
}

export class MemoryPages {

    private memoryPages: MemoryPage[] = []

    constructor() {
        let ranges: RangeDetails[] = Process.enumerateRanges('r--')

        ranges.forEach((range) => {
            this.memoryPages.push(new MemoryPage(range, true))
        })
    }

    // Method to filter memory pages by filename
    public filterByFilename(file_name: string): void {

        this.memoryPages.forEach((memoryPage) => {
            //set the value only if the fileName matches
            memoryPage.setEnabled(memoryPage.getFileName().includes(file_name))
        })
    }

    // Method to filter memory pages by memory range
    public filterByMemoryRange(init_memory: string, end_memory: string): void {
        const inicioDecimal = parseInt(init_memory, 16);
        const finDecimal = parseInt(end_memory, 16);

        this.memoryPages.forEach((memoryPage) => {
            const baseDecimal = parseInt(memoryPage.getBase().toString(), 16);
            memoryPage.setEnabled(baseDecimal >= inicioDecimal && baseDecimal <= finDecimal)
        })
    }

    public resetActiveMemoryPages(): void {
        this.memoryPages.forEach((memoryPage) => {
            memoryPage.setEnabled(true);
        })
    }

    public getValidPages(): MemoryPage[] {
        return this.memoryPages.filter(memoryPage => {
            return memoryPage.isEnabled();
        });
    }

    public getAllPages(): MemoryPage[] {
        return this.memoryPages;
    }
    public displayAllMemoryPages(): void {
        this.memoryPages.forEach((memoryPage) => {
            memoryPage.displayConfig()
        })
    }
}

let memory_pages: MemoryPages | null = null

export const memory = {
    // android clipboard
    startMemoryPages: () => {
        memory_pages = new MemoryPages();
    },
    restartMemoryPages: () => {
        memory_pages = new MemoryPages();
    },
    resetVisibilityMemoryPages: () => {
        memory_pages?.resetActiveMemoryPages();
    },
    getAllMemoryPages: () => {
        return memory_pages?.getAllPages();
    },
    getActiveMemoryPages: () => {
        return memory_pages?.getValidPages();
    },
    filterByFileName: (file_name: string) => {
        memory_pages?.filterByFilename(file_name);
    },
    filterByMemoryRange: (init_memory: string, end_memory: string) => {
        memory_pages?.filterByMemoryRange(init_memory, end_memory);
    },
}
