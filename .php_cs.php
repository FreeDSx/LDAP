<?php
$finder = Symfony\CS\Finder\DefaultFinder::create()
    ->exclude('tests')
    ->in('src')
;
return Symfony\CS\Config\Config::create()
    ->finder($finder)
    ->level(Symfony\CS\FixerInterface::PSR2_LEVEL)
    ;
