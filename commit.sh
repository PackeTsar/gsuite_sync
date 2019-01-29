virtualenv commit_env
source ./commit_env/bin/activate
python setup.py sdist bdist_wheel
python3 setup.py sdist bdist_wheel
twine upload dist/*

deactivate

rm -rf ./gsuite_sync.egg-info
rm -rf build
rm -rf commit_env
rm -rf dist
find . -name "*.pyc" -type f -delete
find . -name "*.log" -type f -delete

