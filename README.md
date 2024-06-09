# Ansible Content
This repo will store various blog posts related to Ansible.

+ [MakingTheDoubleHop](./MakingTheDoubleHop/MakingTheDoubleHop.md) - How to work around credential delegation in Windows
+ [KerberosDelegation - Part 1 Unconstrained](./KerberosDelegation/KerberosDelegation%20-%20Part%201%20Unconstrained.md) - Kerberos Unconstrained Delegation
+ [Windows Tips and Tricks](./WindowsTipsAndTricks/WindowsTipsAndTricks.md) - Tips and Tricks for using Ansible and Windows

See https://github.com/jborean93/ansible-content/discussions/1 for a running list of topics I am hoping to cover.

## Rendering Content
Rendering the docx required the [mermaid-filter](https://github.com/raghur/mermaid-filter) package to render the mermaid graphs.

```bash
npm install mermaid-filter
```

To then render the markdown file change `DOC` to the doc you wish to render.

```bash
DOC="MakingTheDoubleHop"
PATH="./node_modules/.bin:${PATH}" \
    pandoc \
    --output "build/${DOC}.docx" \
    --from markdown \
    --to docx \
    --filter mermaid-filter \
    --no-highlight \
    --reference-doc reference.docx \
    "${DOC}/${DOC}.md"
```
