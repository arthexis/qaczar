
























































GitHub - psf/requests: A simple, yet elegant, HTTP library.















































Skip to content







Toggle navigation










            Sign up
          


 













        Product
        











Actions
        Automate any workflow
      







Packages
        Host and manage packages
      







Security
        Find and fix vulnerabilities
      







Codespaces
        Instant dev environments
      







Copilot
        Write better code with AI
      







Code review
        Manage code changes
      







Issues
        Plan and track work
      







Discussions
        Collaborate outside of code
      



Explore


      All features

    



      Documentation

    





      GitHub Skills

    





      Blog

    








        Solutions
        





For


      Enterprise

    



      Teams

    



      Startups

    



      Education

    





By Solution


      CI/CD & Automation

    



      DevOps

    





      DevSecOps

    





Case Studies


      Customer Stories

    



      Resources

    








        Open Source
        








GitHub Sponsors
        Fund open source developers
      






The ReadME Project
        GitHub community articles
      



Repositories


      Topics

    



      Trending

    



      Collections

    





Pricing

































        In this repository
      

        All GitHub
      
↵


      Jump to
      ↵






No suggested jump to results





















        In this repository
      

        All GitHub
      
↵


      Jump to
      ↵





















        In this organization
      

        All GitHub
      
↵


      Jump to
      ↵





















        In this repository
      

        All GitHub
      
↵


      Jump to
      ↵






 




              Sign in
            


              Sign up
            























        psf
 
/

requests

Public







 

Notifications



 

Fork
    9k




 


          Star
 49.1k
  









        A simple, yet elegant, HTTP library.
      





requests.readthedocs.io/en/latest/


License





     Apache-2.0 license
    






49.1k
          stars
 



9k
          forks
 



 


          Star

  





 

Notifications












Code







Issues
203






Pull requests
67






Actions







Wiki







Security







Insights



 
 



More


 


                  Code
 


                  Issues
 


                  Pull requests
 


                  Actions
 


                  Wiki
 


                  Security
 


                  Insights
 







psf/requests









This commit does not belong to any branch on this repository, and may belong to a fork outside of the repository.











main





Switch branches/tags










Branches
Tags














View all branches















View all tags













Name already in use









      A tag already exists with the provided branch name. Many Git commands accept both tag and branch names, so creating this branch may cause unexpected behavior. Are you sure you want to create this branch?



    Cancel

    Create








6
branches





147
tags







    Code
 







Local



 Codespaces



  










  Clone





            HTTPS
 
            GitHub CLI
 













        Use Git or checkout with SVN using the web URL.
    













      Work fast with our official CLI.
      Learn more.
    








    Open with GitHub Desktop






    Download ZIP



 
Sign In Required

                Please
                sign in
                to use Codespaces.
              



Launching GitHub Desktop

    If nothing happens, download GitHub Desktop and try again.
  




Launching GitHub Desktop

    If nothing happens, download GitHub Desktop and try again.
  




Launching Xcode

    If nothing happens, download Xcode and try again.
  





Launching Visual Studio Code
Your codespace will open once ready.
There was a problem preparing your codespace, please try again.












Latest commit






 




pquentin

Support missing SNIMissingWarning in tests (#6336)




        …
      




        1558590
      

Jan 21, 2023





Support missing SNIMissingWarning in tests (#6336)


1558590



Git stats







6,139

                      commits
                    







Files

Permalink




  
    Failed to load latest commit information.


  
 


Type
Name
Latest commit message
Commit time








.github


 


 









docs


 


 









ext


 


 









requests


 


 









tests


 


 









.coveragerc


 


 









.git-blame-ignore-revs


 


 









.gitignore


 


 









.pre-commit-config.yaml


 


 









AUTHORS.rst


 


 









HISTORY.md


 


 









LICENSE


 


 









MANIFEST.in


 


 









Makefile


 


 









NOTICE


 


 









README.md


 


 









pyproject.toml


 


 









requirements-dev.txt


 


 









setup.cfg


 


 









setup.py


 


 









tox.ini


 


 




    View code
 
















Requests
Installing Requests and Supported Versions
Supported Features & Best–Practices
API Reference and User Guide available on Read the Docs
Cloning the repository





README.md




Requests
Requests is a simple, yet elegant, HTTP library.
>>> import requests
>>> r = requests.get('https://httpbin.org/basic-auth/user/pass', auth=('user', 'pass'))
>>> r.status_code
200
>>> r.headers['content-type']
'application/json; charset=utf8'
>>> r.encoding
'utf-8'
>>> r.text
'{"authenticated": true, ...'
>>> r.json()
{'authenticated': True, ...}
Requests allows you to send HTTP/1.1 requests extremely easily. There’s no need to manually add query strings to your URLs, or to form-encode your PUT & POST data — but nowadays, just use the json method!
Requests is one of the most downloaded Python packages today, pulling in around 30M downloads / week— according to GitHub, Requests is currently depended upon by 1,000,000+ repositories. You may certainly put your trust in this code.



Installing Requests and Supported Versions
Requests is available on PyPI:
$ python -m pip install requests
Requests officially supports Python 3.7+.
Supported Features & Best–Practices
Requests is ready for the demands of building robust and reliable HTTP–speaking applications, for the needs of today.

Keep-Alive & Connection Pooling
International Domains and URLs
Sessions with Cookie Persistence
Browser-style TLS/SSL Verification
Basic & Digest Authentication
Familiar dict–like Cookies
Automatic Content Decompression and Decoding
Multi-part File Uploads
SOCKS Proxy Support
Connection Timeouts
Streaming Downloads
Automatic honoring of .netrc
Chunked HTTP Requests

API Reference and User Guide available on Read the Docs

Cloning the repository
When cloning the Requests repository, you may need to add the -c fetch.fsck.badTimezone=ignore flag to avoid an error about a bad commit (see
this issue for more background):
git clone -c fetch.fsck.badTimezone=ignore https://github.com/psf/requests.git
You can also apply this setting to your global Git config:
git config --global fetch.fsck.badTimezone ignore

 









About

      A simple, yet elegant, HTTP library.
    





requests.readthedocs.io/en/latest/


Topics



  python


  http


  client


  cookies


  requests


  humans


  forhumans


  python-requests



Resources





      Readme
 
License





     Apache-2.0 license
    

Code of conduct





      Code of conduct
    

Security policy





      Security policy
    



Stars





49.1k
    stars

Watchers





1.4k
    watching

Forks





9k
    forks







    Releases
      5







v2.28.2

          Latest
 
Jan 12, 2023

 

        + 4 releases





Sponsor this project



 





https://www.python.org/psf/sponsorship/









        Used by 1.9m
 

























            + 1,919,489
          







    Contributors 619




























































      + 608 contributors





Languages











Python
99.8%







Makefile
0.2%















Footer







 
        © 2023 GitHub, Inc.
        



Footer navigation

Terms
Privacy
Security
Status
Docs
Contact GitHub
Pricing
API
Training
Blog
About
















    You can’t perform that action at this time.
  




You signed in with another tab or window. Reload to refresh your session.
You signed out in another tab or window. Reload to refresh your session.











