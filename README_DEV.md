For Developers
==============

## Tests and coverage report

### python version

First, make sure your python version is `3.6.x`. Some tests will fail with `3.5.x` since some generated easm code is different from `3.6.x`.

Run tests:

```bash
pip3 install -r requirements.txt
./all_tests.sh
```

The tests may save their outputs content to `./tests/testdata/outputs_current/`, you can compare the files between it and `./tests/testdata/outputs_expected/` to see the difference if there is any changes.

If you think the changes are expected, you can just copy them to `outputs_expected` and commit them as new expected outputs.

The `./tests/testdata/outputs_current/` directory is deleted and recreated in `all_tests.sh` and `coverage_report.sh` each time. 

Generate coverage report:

```bash
./coverage_report.sh
```

It will generate the coverage report in `./coverage_html_report/index.html`, and which will be automatically opened in browser.
