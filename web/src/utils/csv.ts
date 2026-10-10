// downloadCSV saves rows as a UTF-8 CSV file (with BOM so Excel opens
// Chinese text correctly). Cells starting with = + - @ are prefixed with a
// quote so spreadsheets do not evaluate them as formulas.
export function downloadCSV(filename: string, header: string[], rows: (string | number | undefined | null)[][]) {
  const cell = (v: string | number | undefined | null) => {
    let s = v === undefined || v === null ? '' : String(v)
    if (/^[=+\-@]/.test(s)) s = `'${s}`
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const text = [header, ...rows].map(r => r.map(cell).join(',')).join('\r\n')
  const blob = new Blob(['﻿' + text], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
