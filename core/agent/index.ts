import { MemoryPage, MemoryPages } from "./process.js"
console.log("printing results")
/*
No test now
memoryPages.forEach((memoryPage) => {
    memoryPage.displayConfig()
})
*/

let memoryPages = new MemoryPages()
memoryPages.filterByFilename("mynativeapplication")
const validMemoryPages: MemoryPage[] = memoryPages.getValidPages()
validMemoryPages.forEach((memoryPage) => {
    memoryPage.displayConfig()
})

console.log("termino 5")