<#Script que verifica compartilhamentos para todos "Share Everyone"
 
 #Criado em 05/2024 - By Anderson Cardoso - versão multidominio
 #Funcionamento:
  
 #Verifica todos os servidores contidos na Infraestrutura do Active Directory, exceto controladores de domínios.
 #Checa em que cada servidor seus compartilhamentos, e adiciona em uma lista aqueles com o "compartilhamento para todos" ativo;
 #Envia um e-mail para área de Segurança com a lista;
 #Envia um e-mail para área de Sustentação com outra lista dos servidores que não conseguiu contactar.

 #Pode ser adicionado ao Task Sheduler caso não possua uma ambiente de orquestração
 #É possivel adicionar um ou mais servidores que não se deseja a verificação, utilizando variável $excludedServers
 #Se necessitar alterar o caminho dos logs, utilize a variável $DefaultPathLogs
 

 #Importante: a conta que irá executar o script, necessita ter um nível de permissão para executar Powershell Remoto e ler informações WMI, para atender este requisito
 #basta que a conta esteja no grupo Remote Management Servers.

 #Altere informações de e-mail no linha que contem Send-EmailWithAttachment

 #> 
 
 #Dominio a ser verificado

$domainName = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name # Obtém o nome do dominio corrente
$domain = $domainName.Split('.')
$domainPrefix = $domain[0]

#CAminho padrão dos Logs
$DefaultPathLogs ="C:\Orchestrator_Logs\ShareEveryone\"

#Registra toda execução do Script em um log
$FilenameLog = $domainPrefix +"_EveryoneShare"

function LogExecution {
        param (
                [Parameter(Mandatory=$true)]
                [string]$LogPath,
		
		        [Parameter(Mandatory=$true)]
                [string]$LogFileName
		
		       
			
		        )
                    #Função para geração de logs, é obrigatório o comando """Stop-Transcript"""" ao término do script Powershell
                    
                    # Exemplo: LogExecution -LogPath "c:\temp\" -LogFileName "Powerloggin"


                    #  Log file time stamp:
                    
                    $LogTime = Get-Date -Format "dd-MM-yyyy_hh-mm"
                   
                    $LogFileName = $LogPath + $LogfileName + "_" + $LogTime+".log"
 
			        #Verifica a existência do caminho

                     if (!(Test-Path -Path $LogPath)){New-Item $LogPath -ItemType Directory}
                                   
		            
                    $logstart=Start-Transcript -Path "$LogFileName" -IncludeInvocationHeader
                    
                    Write-Host "Arquivo de LOG gerado em: " $LogFileName -ForegroundColor DarkGreen
                    $LogAttach+=$LogFileName 
            
                    }

# Lista de servidores que não serão verificados
$excludedServers = @("ServerTeste1", "ServerTeste2", "ServerTesteN")

function Send-EmailWithAttachment {
    param (
        [string]$from,
        [string]$to, # Endereços de e-mail separados por vírgulas
        [string]$subject,
        [string]$body,
        [string]$attachmentPath,
        [string]$smtpServer,
        [int]$smtpPort = 25
    )

    try {
        # Verifica se o anexo existe
        if (-not (Test-Path -Path $attachmentPath)) {
            Write-Host "Anexo não encontrado: $attachmentPath" -ForegroundColor Red
            return
        }

        # Configura os parâmetros do e-mail
        $mailParams = @{
            From        = $from
            To          = $to -split ',' # Divide os endereços separados por vírgulas
            Subject     = $subject
            Body        = $body
            SmtpServer  = $smtpServer
            Port        = $smtpPort
            Attachments = $attachmentPath
            BodyAsHtml  = $true # Corpo do e-mail como HTML
            Encoding    = [System.Text.Encoding]::UTF8 # Codificação UTF-8
        }

        # Envia o e-mail
        $errorVariable = $null
        $null= Send-MailMessage @mailParams -ErrorVariable errorVariable -ErrorAction SilentlyContinue


        if ($errorVariable) {
           Write-Error "Falha ao enviar o e-mail, revise disponibilidade e parametros do servidor, $errorVariable "
            } else {
                    Write-Host "E-mail enviado com sucesso para $to" -ForegroundColor Green
                    }


    } catch {
        Write-Host "Falha ao enviar e-mail: $_" -ForegroundColor Red
    }
}
# Exemplo de uso da função
<#>Send-EmailWithAttachment -from "seu-email@example.com" `
                         -to "destinatario1@example.com,destinatario2@example.com" `
                         -subject "Assunto do E-mail" `
                         -body "<html><body>Corpo do e-mail com acentuação: áéíóú ç ãõ</body></html>" `
                         -attachmentPath "C:\Caminho\Para\Seu\Anexo.txt" `
                         -smtpServer "smtp.seu-servidor.com"
                         #>

function ImprimirTextoEmRetangulo {
    param (
        [string]$Texto,
        [int]$Largura,
        [int]$Altura
    )
    
    # Verificar se o texto cabe dentro do retângulo
    if ($Texto.Length -gt (($Largura - 2) * ($Altura - 2))) {
        Write-Host "O texto é muito grande para caber no retângulo."
        return
    }
    
    # Imprimir o retângulo superior
    Write-Host ('┌' + ('─' * ($Largura - 2)) + '┐')
    
    # Imprimir as linhas intermediárias com o texto
    for ($i = 0; $i -lt ($Altura - 2); $i++) {
        $linha = '│' + (' ' * ($Largura - 2)) + '│'
        if ($i -eq [math]::Floor(($Altura - 2) / 2)) {
            # Inserir o texto na linha central
            $indiceInicial = [math]::Floor(($Largura - $Texto.Length) / 2)
            $linha = $linha.Remove($indiceInicial, $Texto.Length).Insert($indiceInicial, $Texto)
        }
        Write-Host $linha
    }
    
    # Imprimir o retângulo inferior
    Write-Host ('└' + ('─' * ($Largura - 2)) + '┘')
}


LogExecution -LogPath $DefaultPathLogs -LogFileName $FilenameLog



# Defina o caminho para o arquivo CSV de saída com informações de compartilhamento
$csvShares = $DefaultPathLogs+$domainPrefix+"_"+"Shares_Info.csv"
$csvShares_history = $DefaultPathLogs+$domainPrefix+"_"+"Shares_Info_History.csv"

# Defina o caminho para o arquivo CSV de saída com informações de falha
$csvFailedServers = $DefaultPathLogs+$domainPrefix+"_"+"Failed_Servers.csv"
$csvFailedServers_history = $DefaultPathLogs+$domainPrefix+"_"+"Failed_Servers_History.csv"

#Remove arquivo de falhas de comunicação caso exista
if (Test-Path $csvFailedServers) {
                    write-host "Removendo $csvFailedServers gerado anteriormente" -ForegroundColor Magenta
                    remove-item $csvFailedServers  -Force
                   
                    }


function Compare-Files {
# Função para comparar o conteúdo de dois arquivos
    param (
        [string]$Path1,
        [string]$Path2
    )

    # Verificar se os arquivos existem
    if (-Not (Test-Path -Path $Path1)) {
        Write-Host "O arquivo $Path1 não existe."
        return $false
    }

    if (-Not (Test-Path -Path $Path2)) {
        Write-Host "O arquivo $Path2 não existe."
        return $false
    }

    # Ler o conteúdo dos arquivos
    $content1 = Get-Content -Path $Path1 -Raw
    $content2 = Get-Content -Path $Path2 -Raw

    # Comparar o conteúdo dos arquivos
    if ($content1 -eq $content2) {
        return $true
    } else {
        return $false
    }
}


function Compare-CsvFiles {
 # Função para comparar o conteúdo de dois arquivos CSVs
    param (
        [string]$Path1,
        [string]$Path2
    )

    if (-not (Test-Path $Path1)) {
        Write-Output "O arquivo '$Path1' não existe."
        return
    }

    if (-not (Test-Path $Path2)) {
        Write-Output "O arquivo '$Path2' não existe."
        return
    }

    try {
        $csv1 = Import-Csv -Path $Path1
        $csv2 = Import-Csv -Path $Path2

        # Normalizar os dados ordenando e convertendo para string
        $csv1String = $csv1 | Sort-Object | ConvertTo-Csv -NoTypeInformation
        $csv2String = $csv2 | Sort-Object | ConvertTo-Csv -NoTypeInformation

        $differences = Compare-Object -ReferenceObject $csv1String -DifferenceObject $csv2String

        if ($differences) {
            Write-Output "Diferenças encontradas:"
            $differences | ForEach-Object {
                if ($_.SideIndicator -eq "<=") {
                    Write-Output "File $Path1 : $($_ -join ', ')"
                } elseif ($_.SideIndicator -eq "=>") {
                    Write-Output "File $Path2 : $($_ -join ', ')"
                }
            }
        } else {
            Write-host "Os arquivos são idênticos."
            return $true
        }
    } catch {
        Write-Output "Ocorreu um erro ao importar ou comparar os arquivos CSV: $_"
    }
}


function Get-ShareInfo {
    # Função para verificar e obter informações de compartilhamentos
    param(
        [string]$ServerName,
        [array]$excludedServers
    )

    # Verificar se o servidor está na lista de exclusão
    if ($excludedServers -contains $ServerName) {
        Write-Host "O servidor $ServerName está na lista de exclusão. Não será verificado." -ForegroundColor Yellow
        return
    }

    # Verificar se o servidor está acessível
    if (Test-Connection -ComputerName $ServerName -Quiet -Count 1) {
        try {
            # Tente obter as informações do compartilhamento
            $shares = Get-SmbShare -CimSession $ServerName -ErrorAction Stop

            # Inicializar um array para armazenar as informações de compartilhamento
            $sharesList = @()

            # Iterar sobre cada compartilhamento encontrado
            foreach ($share in $shares) {
                # Verificar se o grupo "Everyone" tem permissões para acessar o compartilhamento
                $permissions = Get-SmbShareAccess -Name $share.Name -CimSession $ServerName | Where-Object { $_.AccountName -eq "Everyone" }
                if ($permissions) {
                    $sharesList += [PSCustomObject]@{
                        ServerName = $ServerName
                        ShareName = $share.Name
                        Path = $share.Path
                        Description = $share.Description
                        Permissions = ($permissions | Select-Object -ExpandProperty AccessRight) -join ", "
                    }
                }
            }

            return $sharesList
        } catch {
            Write-Host "Erro ao obter compartilhamentos do servidor $ServerName : $_" -ForegroundColor Red
            Add-Content -Path $csvFailedServers -Value $ServerName 
            Add-Content -Path $csvFailedServers -Value $_
        }
    } else {
        Write-Host "O servidor $ServerName não está acessível." -ForegroundColor Yellow
        Add-Content -Path $csvFailedServers -Value "O servidor $ServerName não está acessível."
    }
}

function Get-Servers {
    # Obtém a lista de todos os domínios da Florest 
    
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $domains = $forest.Domains

    # Inicializa o arry para armazenar o resultado
    $results = @()

    # Loop para procurar os servidres em todos dominios
    foreach ($domain in $domains) {
        # Set the current domain context
        $domainContext = $domain.Name

        # #Consulta a lista de servidores existentes no Active Directory, considera sistemas operacionais Microsoft, e filtra os controladores de domínios.
        $searchResults = Get-ADComputer -Filter {(OperatingSystem -like "*Windows*Server*") -and (Enabled -eq $true) -and (PrimaryGroupID -ne 516)} -Property * -Server $domainContext

        # Adiciona o resultado no arry
        $results += $searchResults
    }

    # Returno o resultado
    return $results | Select-Object Name, DNSHostName, OperatingSystem
}

 

#$Servers = Get-ADComputer -Filter {(OperatingSystem -like "*Windows*Server*" -and Name -like "RDH*") -and (Enabled -eq $true) -and (PrimaryGroupID -ne 516)} -Property * -Server $domainName -SearchScope Subtree

$Servers= Get-Servers

# Inicializar um array para armazenar todas as informações de compartilhamento
$allSharesInfo = @()

# Iterar sobre cada servidor obtido no Active Direcory
foreach ($server in $Servers) {
    $serverName = $server.DNSHostName
    Write-Host "Verificando servidor" $serverName 

    # Obter informações de compartilhamento e adiciona ao array
    $allSharesInfo += Get-ShareInfo -ServerName $serverName -ExcludedServers $excludedServers
}



# Verificar se há compartilhamentos encontrados

if ($allSharesInfo) {
    # Exportar todas as informações de compartilhamento para o arquivo CSV de saída
    $allSharesInfo | Export-Csv -Path $csvShares -NoTypeInformation
    Write-Host "Foram encontrados compartilhamentos que permitem acesso ao grupo 'Everyone'. Verifique $csvShares para mais detalhes." -ForegroundColor Red
    
    

    # Chamado para Segurança da Informação
    
    #Testa a existência de histórico do teste de vulnerabilidade, existindo compara para não gerar chamado duplicado
    if (test-path $csvShares_history) 
       {
        
        $Compare= Compare-CsvFiles -Path1 $csvShares_history -Path2 $csvShares
        

        if ($Compare -eq $true) 
            {ImprimirTextoEmRetangulo -Texto "Não há necessidade de gerar novo chamado para equipe Segurança da  Informação, pois o histórico é o mesmo"   -Largura 110 -Altura 5
            }  else { 
                     ImprimirTextoEmRetangulo -Texto "Gerando um novo chamado para equipe de Segurança da Informação, existem diferenças do histórico"   -Largura 70 -Altura 5               
                     Send-EmailWithAttachment -from "SeuEmailFrom@com.br" -to "SeuEmailTo@com.br" -subject "Report Share Erveryone" -attachmentPath $csvShares -smtpServer seuservidordeemail.com.br -body "Reporte Share Erveryone" 
                     write-host "Atualizando arquivo de history[Vulnerabilidades] para a próxima verificação de Vulnerabilidade"
                     Copy-Item $csvShares $csvShares_history -force
                      }

       }  else {
                ImprimirTextoEmRetangulo -Texto "Gerando um novo chamado para equipe de Segurança da Informação"   -Largura 68 -Altura 5
                Send-EmailWithAttachment -from "SeuEmailFrom@com.br" -to "SeuEmailTo@com.br" -subject "Report Share Erveryone" -attachmentPath $csvShares -smtpServer seuservidordeemail.com.br -body "Reporte Share Erveryone" 
                write-host "Atualizando arquivo de history[Vulnerabilidades] para a próxima verificação de Vulnerabilidade" -ForegroundColor DarkYellow
                Copy-Item $csvShares $csvShares_history -force
                }

    } else 
      {
      Write-Host "Nenhum compartilhamento foi encontrado que permita acesso ao grupo 'Everyone'. Nenhum arquivo CSV foi gerado."
      }


#Chamado para Sustentação

#Compara arquivo de falhas gerado com o histórico para saber se são os mesmos eventos
$Compare_FailedServers= Compare-Files -Path1 $csvFailedServers_history -Path2 $csvFailedServers


#Testa a existência de histórico do teste de vulnerabilidade, existindo compara para não gerar chamado duplicado
if ($Compare_FailedServers -eq $true) 
                   { ImprimirTextoEmRetangulo -Texto "Não há necessidade de gerar novo chamado para Sustentação, pois o histórico é o mesmo"   -Largura 90 -Altura 5
                        
                   } elseif ($Compare_FailedServers  -ne $true) 
                            {
                            ImprimirTextoEmRetangulo -Texto "Gerando um novo chamado para equipe de Sustentação"   -Largura 55 -Altura 5
                            #Write-host "Gerando um novo chamado para equipe de Sustentação" -ForegroundColor red
                            Send-EmailWithAttachment -from "SeuEmailFrom@com.br" -to "SeuEmailTo@com.br" -subject "Report Servidores não contatados" -attachmentPath $csvFailedServers -smtpServer seuservidordeemail.com.br -body "Reporte de Servidores não contatados" 
                            write-host "Atualizando arquivo de history[Erros de comunicação] para a próxima verificação de Vulnerabilidade" -ForegroundColor DarkYellow
                            Copy-Item $csvFailedServers $csvFailedServers_history -force
                            }


#Fim
$logstart = Stop-Transcript