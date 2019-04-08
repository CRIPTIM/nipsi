import setuptools

with open("README.md", "r") as fh: 
    long_description = fh.read()

setuptools.setup(
    name="NIPSI",
    version="1.0.0",
    author="Tim R. van de Kamp",
    description="Proof-of-concept implementation for Non-interactive Private Set Intersection schemes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CRIPTIM/nipsi",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],  
)
