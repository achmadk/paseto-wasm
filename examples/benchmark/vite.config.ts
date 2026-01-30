import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tsconfigPaths from 'vite-tsconfig-paths'

export default defineConfig({
    plugins: [
        tsconfigPaths(),
        react()
    ],
    // resolve: {
    //     alias: {
    //         'paseto-wasm': "../../pkg/paseto_wasm.js",
    //     },
    // },
})
