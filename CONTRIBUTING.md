# 🚀 Contributing to Microsandbox

Hello there! Whether you're a seasoned developer or just getting started, we're thrilled that you're interested in contributing to Microsandbox. This community thrives because of people like you!

## 👋 Welcome, New Contributors!

Never contributed to open source before? No problem! We've all been there. We've tagged issues with [good first issues][good-first-issues] to help you find a comfortable starting point. Remember, every expert was once a beginner!

## 🤔 Need Help?

We're here for you! Reach out to us at [team@microsandbox.dev][support-email] with any questions. This guide is designed to help you get started, so don't worry if it seems detailed - it's meant to be thorough, not intimidating!

## 💖 Code of Conduct

Our community values kindness and inclusivity. Please take a moment to read our [code of conduct](./CODE_OF_CONDUCT.md) and help us maintain a welcoming environment for everyone.

## 🛠️ How to Contribute

There are many ways to contribute to Microsandbox, and we appreciate them all! Here's how to get started:

### 💡 Contributing Ideas and Feedback

#### Issues

Found a bug or have a feature idea? We'd love to hear about it! ❤️

Before creating a new issue, please search existing ones to avoid duplicates. Then just hit the issue button, choose a template, and share your thoughts. Don't worry if you can't fill out the entire template - share what you can and you can always update it later.

#### Discussions

For topics that aren't quite bugs or feature requests, start a [GitHub discussion][gh-discussions]. Great discussion topics include:

- Community announcements or asking for feedback
- Discussing upcoming releases
- General questions about the project
- Sharing your experience with Microsandbox

### 💻 Contributing Code

You don't need to be an expert programmer to contribute code! Here's a friendly step-by-step guide:

1. **Find something to work on**

   - Browse our existing issues or create a new one if you have a fresh idea

2. **Join the conversation**

   - Comment on the issue you'd like to work on
   - This helps prevent duplicate work and lets you get valuable input from the community
   - Don't be shy - we're a friendly bunch!

3. **Fork the repository**

   - This creates your own copy of the code to work with
   - New to forking? Learn more [here][forking]

4. **Set up commit signing**

   - This verifies that commits come from you
   - Follow [this guide][commit-signing] to set it up
   - Already made unsigned commits? No worries! [Here's how to fix that][post-signing]

5. **Clone the repository**

   - This puts your fork on your local machine
   - Need help? Check out [this guide][git-clone]

6. **Build the project**

   - Follow the instructions in our [DEVELOPMENT.md](./DEVELOPMENT.md) file
   - If you run into any issues, remember we're just an email away!

7. **Install pre-commit hooks**

   - Install `pre-commit` with your package manager, for example `brew install pre-commit` or `pipx install pre-commit`
   - Run `pre-commit install` from the repository root
   - Optional but recommended: run `pre-commit run --all-files` once before your first commit

8. **Make your changes**

   - Open your favorite editor and start coding
   - Test your changes using the commands in our README
   - Take breaks and have fun with it!

9. **Write tests**

   - For new features: Write tests that protect your feature from breaking
   - For bug fixes: Write tests that ensure the bug won't return
   - Consider adding documentation tests to show how to use your new feature
   - Don't stress about getting testing perfect - we can help guide you

10. **Follow coding guidelines**

    - Check out our [Rust style guide][rust-style-guide] for reference
    - Clean, readable code helps everyone who comes after you
    - If you're unsure about anything, just do your best and mention it in your PR

11. **Commit and push your changes**

    - Send your work to your GitHub repository
    - We use [conventional commits][conventional-commits] for naming
    - New to Git? Learn about [committing code][committing-code] and [pushing][push-remote]
    - Pre-commit hooks will run automatically if you installed them

12. **Open a pull request** 🎉
    - This is how your code gets merged into the main project
    - We'll review your code and may suggest some changes
    - Every pull request helps us grow, so thank you in advance!
    - Learn more about [pull requests here][prs]

## 🙏 Thank You!

Every contribution, no matter how small, makes a difference. We're grateful for your interest in making Microsandbox better for everyone!

[conventional-commits]: https://www.conventionalcommits.org/en/v1.0.0/
[committing-code]: https://docs.github.com/en/desktop/contributing-and-collaborating-using-github-desktop/making-changes-in-a-branch/committing-and-reviewing-changes-to-your-project
[commit-signing]: https://www.freecodecamp.org/news/what-is-commit-signing-in-git/
[forking]: https://docs.github.com/en/get-started/quickstart/fork-a-repo
[gh-discussions]: https://docs.github.com/en/discussions
[git-clone]: https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository
[good-first-issues]: https://github.com/monoceros-alpha/monocore/labels/good%20first%20issue
[post-signing]: https://dev.to/jmarhee/signing-existing-commits-with-gpg-5b58
[prs]: https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests
[push-remote]: https://docs.github.com/en/get-started/using-git/pushing-commits-to-a-remote-repository
[rust-style-guide]: https://rust-lang.github.io/api-guidelines/about.html
[test-org]: https://doc.rust-lang.org/book/ch11-03-test-organization.html
[support-email]: mailto:team@microsandbox.dev
[unit-and-integration]: https://www.geeksforgeeks.org/difference-between-unit-testing-and-integration-testing/
