import { MemoryPage, MemoryPages } from "./process.js"
console.log("printing results")
/*
No test now
memoryPages.forEach((memoryPage) => {
    memoryPage.displayConfig()
})


let memoryPages = new MemoryPages()
memoryPages.filterByFilename("mynativeapplication")
const validMemoryPages: MemoryPage[] = memoryPages.getValidPages()
validMemoryPages.forEach((memoryPage) => {
    memoryPage.displayConfig()
})
*/

let variable: number = 5

rpc.exports = {
    readVariable: (): number => { return variable },
    writeVariable: (my_number: number) => { variable = my_number }
}
console.log("termino 5")