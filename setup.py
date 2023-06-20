import os
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="FlowAnalyzer",
    version="0.1.1",
    description="FlowAnalyzer是一个流量分析器，用于解析和处理tshark导出的JSON数据文件",
    author="Byxs20",
    author_email="97766819@qq.com",
    packages=find_packages(exclude=["tests", "*.egg-info"]),
    package_data={
        '': ['LICENSE', 'README.md', 'setup.py'],
    },
    install_requires=[
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],

    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Byxs20/FlowAnalyzer",
)
