from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='docsingest',
    version='0.1.0',
    author='Marc Shade',
    author_email='marc@2acrestudios.com',
    description='AI-powered document ingestion tool with compliance features',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/marc-shade/docsingest',
    packages=find_packages(),
    install_requires=[
        'PyPDF2>=3.0.1',
        'python-docx>=0.8.11',
        'markdown>=3.4.3',
        'tiktoken>=0.4.0',
        'chardet>=5.1.0',
        'requests>=2.26.0'
    ],
    entry_points={
        'console_scripts': [
            'docsingest=docsingest.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Text Processing',
        'Topic :: Utilities'
    ],
    keywords='document-processing ai compliance llm text-extraction',
    python_requires='>=3.8',
    project_urls={
        'Bug Reports': 'https://github.com/marc-shade/docsingest/issues',
        'Source': 'https://github.com/marc-shade/docsingest',
    },
)
