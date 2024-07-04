#Script que verifica Share com permissão Everyone, permite lista de exceção e não verifica controladores de dominio


# Defina o caminho para o arquivo CSV de saída com informações de compartilhamento
$csvOutputPath = "shares_info.csv"

# Defina o caminho para o arquivo CSV de saída com informações de falha
$csvFailedPath = "failed_servers.csv"

# Lista de servidores que não serão verificados
$excludedServers = @("ADPOA123", "ADPOA165", "ADPOA123")

# Função para verificar e obter informações de compartilhamento
function Get-ShareInfo {
    param(
        [string]$ServerName,
        [array]$ExcludedServers
    )

    # Verificar se o servidor está na lista de exclusão
    if ($ExcludedServers -contains $ServerName) {
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
            Add-Content -Path $csvFailedPath -Value $ServerName
        }
    } else {
        Write-Host "O servidor $ServerName não está acessível." -ForegroundColor Yellow
        Add-Content -Path $csvFailedPath -Value $ServerName
    }
}

# Solicitar ao usuário o nome do domínio
$domainName = Read-Host "Digite o nome do domínio que deseja verificar (deixe em branco para o domínio atual)"

# Obter servidores Microsoft no domínio especificado, incluindo subdomínios
$servers = Get-ADComputer -Filter {(OperatingSystem -like "*Windows*") -and (Enabled -eq $true)} -Property * -Server $domainName -SearchScope Subtree
$servers = Get-ADComputer -Filter {(OperatingSystem -like "*Windows*Server*") -and (Enabled -eq $true) -and (PrimaryGroupID -ne 516)} -Property * -Server $domainName -SearchScope Subtree

# Inicializar um array para armazenar todas as informações de compartilhamento
$allSharesInfo = @()

# Iterar sobre cada servidor
foreach ($server in $servers) {
    $serverName = $server.Name
    Write-Host "Verificando servidor $serverName..."

    # Obter informações de compartilhamento e adicionar ao array
    $allSharesInfo += Get-ShareInfo -ServerName $serverName -ExcludedServers $excludedServers
}

# Verificar se há compartilhamentos encontrados
if ($allSharesInfo) {
    # Exportar todas as informações de compartilhamento para o arquivo CSV de saída
    $allSharesInfo | Export-Csv -Path $csvOutputPath -NoTypeInformation
    Write-Host "Foram encontrados compartilhamentos que permitem acesso ao grupo 'Everyone'. Verifique $csvOutputPath para mais detalhes."
} else {
    Write-Host "Nenhum compartilhamento foi encontrado que permita acesso ao grupo 'Everyone'. Nenhum arquivo CSV foi gerado."
}
