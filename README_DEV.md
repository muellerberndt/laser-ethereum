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

Generate coverage report:

```bash
./coverage_report.sh
```

It will generate the coverage report in `./coverage_html_report/index.html`, and which will be automatically opened in browser.
