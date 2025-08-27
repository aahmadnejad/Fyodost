from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="fyodost",
    version="1.0.0",
    description="Fyodost — Your all-in-one Layer 2 offensive arsenal, complete control over the Layer 2 battlefield.",
    author="AAhmadnejad",
    author_email="a.ahmadnejad007@gmail.com",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    package_data={
        'fyodost': ['utils/*.py', 'attacks/*.py'],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Offensive/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "fyodost=fyodost.main:main",
        ],
    },
    include_package_data=True,
)