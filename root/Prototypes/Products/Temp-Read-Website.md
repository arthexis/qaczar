






















































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
 49k
  









        A simple, yet elegant, HTTP library.
      





requests.readthedocs.io/en/latest/


License





     Apache-2.0 license
    






49k
          stars
 



9k
          forks
 



 


          Star

  





 

Notifications












Code







Issues
201






Pull requests
65






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



ci: add minimum GitHub token permissions for workflows (#6236)



January 11, 2023 15:06









docs



Replace git protocol URL in docs with an HTTPS URL



November 21, 2022 14:01









ext



The Principle of Polarity



September 23, 2019 14:17









requests



v2.28.2



January 12, 2023 09:16









tests



Support missing SNIMissingWarning in tests (#6336)



January 21, 2023 01:44









.coveragerc



Add automatic code formatting to Requests (#6095)



April 29, 2022 13:16









.git-blame-ignore-revs



Add .git-blame-ignore-revs



April 29, 2022 15:39









.gitignore



Switch LGPL'd chardet for MIT licensed charset_normalizer (#5797)



July 6, 2021 18:55









.pre-commit-config.yaml



Update flake8 repo and version (#6317)



December 25, 2022 21:24









AUTHORS.rst



Send only one Host header in chunked request



September 2, 2021 00:53









HISTORY.md



v2.28.2



January 12, 2023 09:16









LICENSE



Apply the Apache-2.0 license correctly



August 27, 2020 09:44









MANIFEST.in



Remove Pipfile/Pipfile.lock



November 11, 2020 10:29









Makefile



Remove Python 2 mention from tox (#6200)



July 20, 2022 17:13









NOTICE



Apply the Apache-2.0 license correctly



August 27, 2020 09:44









README.md



Farewell, sweet Concorde!



March 25, 2022 10:50









pyproject.toml



Add automatic code formatting to Requests (#6095)



April 29, 2022 13:16









requirements-dev.txt



Fix jinja



February 18, 2022 18:33









setup.cfg



Allow charset normalizer >=2 and <4 (#6261)



October 20, 2022 12:26









setup.py



fix: Remove '<4' from python_requires (#6333)



January 18, 2023 22:37









tox.ini



Switch to Python 3.11 final on CI and add to tox file (#6325)



January 6, 2023 11:32




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





49k
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









        Used by 1.8m
 




























            + 1,818,532
          







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











