# Approved detections

Sigma rules approved by a reviewer on screen 3 of the console (or with `./tip detections review`). Each file starts with
an "Approved by" line and has `status: test`: deploy it in test mode and watch it before promoting it to `stable`.

Re-test any rule against the replay datasets:

```bash
./tip detections test detections/<rule>.yml
```

Rules here are only ever added by an approval and removed by a withdrawal; drafts and failed rules stay in the database.
