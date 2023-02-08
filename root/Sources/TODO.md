- Resolve sigils and try to capture additional context in script output.
    - Test-Screenshots should work properly after that.
- 

## IDEAS
- Run upstream nodes in parallel.
    - There are reasons to do and not to do this, we should justify the change.
- Create a flashy use-case, brainstorm:
    - Script to capture multiple screenshots in a folder?
    - Display the result of SQL queries.
- Figure out a way to reload the Obsidian window after starting the build, or after changes have been made to the canvas file.


## DONE
- Remove duplicated outputs produced by markdown python code blocks. 
    - CAUSE: Nodes are being evaluated twice because there are two target nodes at the end and each triggers a separate run. Choose what to do:
        - **Option 1: Avoid re-running a node twice, ie by checking if it is already green.**
            - This makes sense because the product is already "produced".
            - In what case would we produce it again? 
            - We have to make sure all TARGETS are fulfilled on the first execution.
- Handle labels on edges. Decide what to do with them.
    - Idea: assign the output of the node to a context variable named in the label edge. Resolve sigils in the label first to allow conditional redirection of content
- Create a sigil filter to handle IMG -> with option to pass ALT text as param.
    - Should generate markdown code for referencing the img.