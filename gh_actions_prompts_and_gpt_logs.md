##@@ initial prompt 

Review this prompt and help me reorganize this prompt as a series of prompts with smaller easier verifyable series of tasks to acheive the overall plan objective

{{{

gh actions tutorial:

I want to create a project-based tutorial for myself to learn the most common and useful GitHub Actions.
In this project create a simple calulator as an example python library module with some unit tests and fuzz tests.

The library module must implement atlease 2 APIs. 
To demonstrate the usefulness of dev-sec-ops tools, you will provide both good and bad versions of these APIs and identify them so using the API_good(), API_bad() naming pattern. The known bad versions of the API shall demonstrate problems that can be discovered by linting, static code analysis, unit testing, fuzz testing.


You will provide both good and bad versions of these APIs and identify them so using the API_good(), API_bad() naming pattern. 
 
I want to use this project to learn dev-ops and more importantly software security or dev-sec-ops. 

I will like to use python version 3.11 using using a virtualenv managed by the pyenv tooling

I am using an Ubuntu 24.04 LTS local host. I can use git and/or the GitHub CLI. 
I will use the 'lgtkgtv' GitHub account. 
I will like to create a git repository for the project and name it 'gh_actions'. Make this an open-source and public accessible project.

Since this will be an open-source and public accessible project, i will like to know what security tools (example Coverity) I can use free of cost to perform security related code scans to maximize security assurance. You shall not only list these tools, but provide instructions to setup and configure scans using each of these tools.   

I don't want to use any cloud accounts yet. 
I want to use a docker container environment to build, test and deploy the project. 
Please provide a script named 'build.sh' to create a docker image consisting of all the tools to build the project, and then execute all the workflows. 

I am proposing following directory structure, but you can improve upon this.

```
project-setup.sh  # this script shall create the project structure and all the files with their contents. 

gh_actions/
    ├── calculator/
    │   ├── src/
    │   ├── test/
    │   └── fuzz/
    ├── build.sh
    ├── Dockerfile
    ├── requirements.txt
    ├── .github/workflows/
    ├── README.md
    └── .gitignore
```

Provide all the code, scripts, and step-by-step instructions for all the commonly used GitHub Actions workflows.

Please also provide a `project-setup.sh` script to create the project's directory structure and populate all the code, scripts, and instructions in each file. 

The bash script to setup the project must be idempotent and install all required tools like pyenv, virtualenv, and docker if they are not present.
The script must check if these tools are already present and not reinstall them unnecessarily. 

Please explain all manual steps in a README.md file.

You will illustrate the GitHub Actions workflows related to:

* Create an empty github project        
* Clone the project on my local host    
* Use the 'project-setup.sh' script to automatically you pr to create the project locally 
* Commit code changes and push code changes to the remote 
* Create a PR 
* Generating automatic code reviews triggered upon a PR.
* Automatic linting using Bandit.
* Automatic static code analysis using Semgrep and Coverity.
* Automatic unit testing using pytest and Hypothesis.
* Automatic fuzz testing for 20 seconds using Atheris.
* Automatic packaging and deployment of the Python library.
* Automated generation of an SW BOM and checking for known vulnerabilities in third-party components and dependencies using `cyclonedx-bom`.
* Automated container scans using the Trivy tool.

The GitHub Actions workflows should be broken down into the following stages:

* Linting and static analysis (Bandit, Semgrep, Coverity)
* Unit testing (pytest with Hypothesis)
* Fuzz testing (Atheris)
* Packaging and publishing (setup.py, PyPI)
* Docker image build and scan (Trivy)
* SBOM generation and vulnerability check.

For Linting and Static Code Analysis:

* For each security tool (Bandit, Semgrep, Trivy), please explain:
    * What type of vulnerabilities it detects.
    * How to interpret the results.
    * Best practices for addressing the identified issues.
* Explain the Coverity scan setup and outputs.

Once the library project is created, provide some code to test the functionality.
Incrementally add unit tests and fuzz tests to the example project for code quality assurance.

About Unit Tests:

* Explain your choice of pytest as a Python unit test framework.
* In the unit tests and fuzz tests, demonstrate how to use the Hypothesis library for writing better tests. Provide examples of using Hypothesis to generate test cases for the calculator functions, including edge cases.

About Fuzz Testing:

* Use the Atheris fuzzing engine.
* Provide a mechanism to trigger fuzzing manually and store the test corpus.
* Provide a mechanism to generate code coverage reports using the existing test corpus.



About SBOM Generation:

* Use `cyclonedx-bom` for SBOM generation.
* Explain how to integrate the SBOM into the workflow and how to check for vulnerabilities.


Know that I am a teacher and want to teach DevSecOps BKMs based on this tutorial.

I am concerned about security topics related to:

* SW BOM and known vulnerabilities in frameworks and libraries.
* Linting.
* Code review.
* Static code analysis.
* Unit testing.
* Fuzzing.
* Secret Scanning.

* Please also illustrate robust error handling in GitHub Actions workflows.
* Demonstrate how to log errors and warnings effectively.
* Explain how to create GitHub issues based on the logs.
* Explicitly mention the use of GitHub's secret scanning feature and how to address identified secrets.
* Make sure each file has a comment block at the top explaining its use.
* Provide very clear, step-by-step instructions for each stage of the tutorial.

}}}



---

To break this prompt into smaller, verifiable tasks, I propose the following step-by-step structure:

### **Phase 1: Project Setup**
1. **Create a New GitHub Repository**
   - Instructions to create an empty repo on GitHub using either web UI or GitHub CLI.
2. **Clone the Repository Locally**
   - Commands for cloning the project to the Ubuntu 24.04 desktop.
3. **Write `project-setup.sh` Script**
   - The script will:
     - Create the specified folder structure.
     - Add initial README, `.gitignore`, and sample code files.
     - Install `pyenv`, `virtualenv`, and `docker` if missing.
   - Test the script to ensure it is idempotent.
4. **Push Initial Project Structure to GitHub**
   - Commit and push the generated structure to the remote repository.

---

### **Phase 2: Implement Core Project Code**
1. **Write a Simple Calculator Library**
   - Implement `API_good()` and `API_bad()` methods with clear explanations of their issues.
2. **Add Unit Tests for Calculator**
   - Demonstrate `pytest` for core functionality testing.
   - Add Hypothesis-based tests for generating edge cases.
3. **Add Fuzz Testing with Atheris**
   - Provide a sample fuzzing test that runs for 20 seconds.
4. **Add a Dockerfile and `build.sh` Script**
   - Create a Docker image containing all dependencies.
   - Ensure the image can build, test, and run the project.

---

### **Phase 3: GitHub Actions for CI/CD**
1. **Create `.github/workflows/` Folder**
2. **Workflow 1: Linting and Static Analysis**
   - Setup Bandit, Semgrep, and Coverity scans.
   - Provide guidance on interpreting results and addressing issues.
3. **Workflow 2: Unit Testing**
   - Automate unit tests with `pytest` and `Hypothesis`.
4. **Workflow 3: Fuzz Testing**
   - Run Atheris fuzz testing as part of the CI pipeline.
5. **Workflow 4: Packaging and Deployment**
   - Automate Python package creation and push to PyPI.
6. **Workflow 5: Docker Build and Trivy Scan**
   - Build the Docker image and scan it for vulnerabilities using Trivy.
7. **Workflow 6: SBOM Generation**
   - Integrate `cyclonedx-bom` for generating an SBOM.
   - Automate vulnerability checking using the SBOM.


---

### **Phase 4: Enhancing Security and Reporting**
1. **Add Secret Scanning**
   - Instructions to enable GitHub's secret scanning feature.
   - Recommendations for addressing flagged secrets.
2. **Create Robust Error Handling in Workflows**
   - Examples of detecting errors and logging them effectively.
3. **Automate GitHub Issue Creation from Logs**
   - Demonstrate how to automatically raise issues for failed tasks or identified security concerns.

---

### **Phase 5: Documentation**
1. **Write a Detailed `README.md`**
   - Instructions for:
     - Running the project locally.
     - Running tests, fuzz tests, and security scans.
     - Using the `build.sh` script.
2. **Add Comment Blocks to Code**
   - Ensure all files have clear comments explaining their purpose.
3. **Provide Best Practices for Each Security Tool**
   - Clear steps for interpreting scan results and addressing vulnerabilities.

---

### **Phase 6: Final Review and Testing**
1. **Verify Each Step**
   - Test the complete setup from scratch to ensure everything works as intended.
2. **Perform a Full CI/CD Pipeline Run**
   - Ensure that all GitHub Actions workflows succeed.
3. **Confirm Security Best Practices**
   - Validate Bandit, Semgrep, Coverity, and Trivy scan outputs.

---

### **Deliverables Checklist**
- `project-setup.sh` (Idempotent)
- `build.sh` (Docker-based build & test)
- Calculator Library with `API_good()` and `API_bad()` 
- Unit tests (with `pytest` + Hypothesis)
- Fuzz tests (with `Atheris`)
- `.github/workflows/` with:
  - Linting and Static Analysis
  - Unit Testing
  - Fuzz Testing
  - Packaging and Deployment
  - Docker Build and Scan
  - SBOM Generation
- Comprehensive `README.md` with clear instructions

---

Would you like me to start by writing the `project-setup.sh` script or focus on another step first?

##@@ Yes, provide instructions for Phase 1: Project Setup. Be concise. Also write the 'project-setup.sh' script

### **Phase 1: Project Setup Instructions**

1. **Create a New GitHub Repository**
   - Visit [GitHub](https://github.com) and log in.
   - Create a new repository named **`gh_actions`** (set it to **public**).
   - Skip adding a README or `.gitignore` (the script will generate them).

2. **Clone the Repository Locally**
   ```bash
   git clone git@github.com:lgtkgtv/gh_actions.git
   cd gh_actions
   ```

3. **Run the `project-setup.sh` Script**
   - Save the provided `project-setup.sh` script to your project root.
   - Make the script executable:
     ```bash
     chmod +x project-setup.sh
     ```
   - Run the script:
     ```bash
     ./project-setup.sh
     ```

**file: gh_actions/project-setup.sh**

```sh
#!/bin/bash

# Idempotent script to set up the project structure and dependencies
set -e  # Exit on error

# Install pyenv if not present
if ! command -v pyenv &> /dev/null; then
  curl https://pyenv.run | bash
  echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
  echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
  echo 'eval "$(pyenv init --path)"' >> ~/.bashrc
  source ~/.bashrc
fi

# Install virtualenv if not present
if ! command -v virtualenv &> /dev/null; then
  pip install virtualenv
fi

# Install Docker if not present
if ! command -v docker &> /dev/null; then
  sudo apt-get update && sudo apt-get install -y docker.io
fi

# Create project structure
cd ..
mkdir -p gh_actions/calculator/src
mkdir -p gh_actions/calculator/test
mkdir -p gh_actions/calculator/fuzz
mkdir -p gh_actions/.github/workflows

# Add initial files
touch gh_actions/README.md
cat << EOF > gh_actions/.gitignore
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.db
*.sqlite3
.vscode/
.DS_Store
EOF

# Success message
echo "✅ Project setup completed successfully."
```

4. **Commit and Push Changes**
   ```bash
   git add .
   git commit -m "Initial project setup"
   git push origin main
   ```

Your project is now ready with the intended structure and necessary tools. Would you like to proceed with the calculator implementation or start writing GitHub Actions workflows next?

##@@ yes
### **Phase 2: Implement Core Project Code**

We'll now:

✅ Implement a simple **calculator** library with `API_good()` and `API_bad()` methods.  
✅ Add **unit tests** using `pytest` and `Hypothesis`.  
✅ Create a **fuzz testing** setup using `Atheris`.  

I'll start by writing the calculator code, unit tests, and fuzz tests. Stay tuned.

I've added the following components to your project setup:

✅ `calculator.py` — Implements `API_good()` and `API_bad()` methods.  
✅ `test_calculator.py` — Includes basic unit tests for both APIs.  

Next, I'll add fuzz testing with `Atheris` and expand the unit tests with `Hypothesis`. Would you like me to proceed?

##@@ Yes

