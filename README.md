# Ansible Content
This repo will store various blog posts related to Ansible.

+ [MakingTheDoubleHop](./MakingTheDoubleHop/MakingTheDoubleHop.md) - How to work around credential delegation in Windows

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
