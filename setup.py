from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='docsingest',
    version = "0.1.28",
    description='📄 AI-Powered Document Analysis Tool for Comprehensive Document Processing',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Marc Shade',
    author_email='marc@2acrestudios.com',
    url='https://github.com/marc-shade/docsingest',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'docsingest=docsingest.cli:main',
        ],
    },
    install_requires=[
        'requests>=2.25.1',
        'chardet>=3.0.4',
        'tiktoken>=0.3.3',
        'markdown>=3.3.4',
        'python-docx>=0.8.11',
        'openpyxl>=3.0.7',
        'PyPDF2>=1.26.0',
        'nltk>=3.6.2',
        'spacy==3.7.4',
        'regex>=2024.1.0,<2025.0.0'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Legal Industry',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Text Processing :: General',
        'Topic :: Scientific/Engineering :: Information Analysis',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities'
    ],
    keywords='document-analysis ai compliance pii-detection semantic-compression llm text-extraction',
    python_requires='>=3.8',
    project_urls={
        'Bug Reports': 'https://github.com/marc-shade/docsingest/issues',
        'Source': 'https://github.com/marc-shade/docsingest',
    },
)
