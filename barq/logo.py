"""
Isolated file for tool's logo, this is needed to clean up core logic

"""


def get_logo() -> str:
    '''
    Barq logo will be shown once the tool is run

    '''
    return """
                                                                                                    
                                                  .                                                 
                                                 :y-                                                
                                                :yy:                                                
                                               /ys/:`                                               
                                              /yo/::-                                               
                                             /y+/::::`                                              
                                            +y/+:::::-                                              
                                           +s:+:::::::`                                             
                                         `+s-+::::::::-                                             
                                        `oo.o/:::::::-`                                             
                                       `o+.o/::::::::                                               
                                      `o/`s/::::::/o:                                               
                                     `o:`s+::::::/sy`                                               
                                    .o-`s+-----::+++..........`                                     
                        `          .+.`so-------------------::`         .`                          
                    ``.--`        .+``so-----:::::::::-----:-`          oys+-.`                     
                `..---..`        ./ `ys----::/+++++oo/----:-            .:+yhhyo:.`                 
            `.----.``           .: `ys:---::+oyssooo+----::....```          .-+shhyo/-`             
       ``.----.``              .- `yh+++++ooooo+//::----:.   ``     `           `-/oyhhs+:``        
     .----.`                  ..  :/::-..``      `-----:--:/+o/    `                 .:+ydhy:       
     .----.`                 .`               `..-----/ssssss+   `.                 `.:oydhy:       
       ``.----.`            `         ``.-:/+os/----:+ysssss+   .-              `-/oydhy+:.         
           ``.----.``          `.--:/+ooossssy/----:+osssss+`  --           `-+shhhs/-`             
                `..---..`   ````    `-ooooosyys+/::ossoooo+`  :-        `:oyddyo:.                  
                    ``.--`           /oooosyyyysooosooooo+`  /-         shs+-`                      
                                   `+ooooooooooooooooooo+` `+-          `                           
                                  .oooooooooooooooooooo+` .o-                                       
                                  .//////////yyyso+++++` -s-                                        
                                             yys++++++` :s-                                         
                                             oo++++++. /s-                                          
                                            `/++++++.`+o.                                           
                                           ./++++++.`oo.                                            
                                           :////+/..so-                                             
                                           ./////.:y+-                                              
                                           `////-/y+-                                               
                                            ://-+y+-                                                
                                       
                                            ./:oy+-                                                 
                                            `/sy/-                                                  
                                             oy/-                                                   
                                             //-                                                    
                         `--.                `-                                                     
                         -dd/                                                                       
                         -dd/`-:-`    `.----.`     `..``---`   `---``..                             
                         -ddysyhdy:   :sooooys:    /yyossss/  -sysoosyy`                            
                         -ddy` `ydh`  ..---:sys    /yy+`  `` `yyo` `syy`                            
                         -dd+   odd. .oyyo++yyy    /yy.      .yy/   +yy`                            
                         -ddy``.hdh  /yy:  `yyy    /yy.      `yys```syy`                            
                         -hhsyyhhy-  .sys++osyy    /yy.       -syyossyy`                            
                         `..``--.      ..-. ...    `..          .-. +yy`                            
                                                                    +yy`                            
                                                                    `..                             
                                                                                                    
"""

def get_welcome_msg() -> str:
    '''
    Welcome message to be displayed for the users once the tool is run
    '''
    return "barq: The AWS post exploitation framework written by Mohammed Aldoub @Voulnet"
