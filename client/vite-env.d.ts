/// <reference types="vite/client" />
import type { AppAPI } from './src/types';
declare global { interface Window { api: AppAPI } }
