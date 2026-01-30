import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
    plugins: [react()],
    server: {
        port: 3000,
    },
    build: {
        target: 'esnext',
    },
    resolve: {
        alias: {
            'paseto-wasm': './pkg/paseto_wasm.js',
        },
    },
})
