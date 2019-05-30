from setuptools import setup, find_packages


setup(
    name="pyvrf",
    version="0.0.1",
    packages=find_packages(),
    requires=["libsodium"],
)
