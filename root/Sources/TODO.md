- Create a sigil filter to handle IMG -> with option to pass ALT text as param.
    - Should generate markdown code for referencing the img.
- Handle arrows pointing to self:
    - Indicates that the node should be blanked before receiving its inputs?
    - If a label is used, save the old content of the node to that context var.
    - 

## IDEAS
- Run upstream nodes in parallel.
    - There are reasons to do and not to do this, we should justify the change.
- Create a flashy use-case, brainstorm:
    - Script to capture multiple screenshots in a folder?
    - Display the result of SQL queries.
- Figure out a way to reload the Obsidian window after starting the build, or after changes have been made to the canvas file.


## DONE
- Handle labels on edges. Decide what to do with them.
    - Idea: assign the output of the node to a context variable named in the label edge. Resolve sigils in the label first to allow conditional redirection of content
