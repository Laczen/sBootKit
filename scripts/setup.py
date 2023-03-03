import setuptools

setuptools.setup(
    name="sbktool",
    version="0.0.1",
    author="LaczenJMS",
    description=("sBootKit image signing and key management"),
    license="Apache Software License",
    url="",
    packages=setuptools.find_packages(),
    install_requires=[
        'pycryptodome>=3.10.1',
        'intelhex>=2.2.1',
        'click',
    ],
    entry_points={
        "console_scripts": ["sbktool=sbktool.main:sbktool"]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 4 - Beta",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: Apache Software License",
    ],
)
