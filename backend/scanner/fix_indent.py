with open('backend/scanner/tasks.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if line.strip() == "_mark_job_completed(scan_job_id)":
        # Find the indentation of the previous line "if mark_completed:"
        if i > 0 and lines[i-1].strip() == "if mark_completed:":
            prev_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
            lines[i] = " " * (prev_indent + 4) + "_mark_job_completed(scan_job_id)\n"
            
with open('backend/scanner/tasks.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)
