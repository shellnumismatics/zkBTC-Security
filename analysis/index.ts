import { execSync } from "node:child_process";
import { inherits } from "node:util";

export default function main() {
    execSync("node dist/analysis/src/timestamp_compute.js > output/ts_compute.out")
    execSync("node dist/analysis/src/cp_compute_all > output/cp_compute_all.out")
}

main()