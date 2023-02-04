### Build and Install Local Package
Run the following lines in the directory of your package to make sure it is locally installed and executing properly before uploading to PyPI.

```shell
python -m pip install -y .
python -m [PACKAGE] --version
python -m [PACKAGE] --test
```

Then to build the latest distribution and upload to PyPI, you will need your credentials:
- [PYPI_USERNAME] 
- [PYPI_PASSWORD]

```shell
python -m build
python -m twine upload dist/* --skip-existing
```