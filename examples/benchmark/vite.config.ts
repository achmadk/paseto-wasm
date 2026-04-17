import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
    plugins: [
        react()
    ],
    resolve: {
        tsconfigPaths: true
    }
    // resolve: {
    //     alias: {
    //         'paseto-wasm': "../../pkg/paseto_wasm.js",
    //     },
    // },
})
