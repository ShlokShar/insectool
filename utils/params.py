from utils.imports import *


def find_parameters(url):
    request = requests.get(url)
    soup = BeautifulSoup(request.content, 'html.parser')
    inputs = []

    for form in soup.find_all('form'):
        for form_input in form.find_all('input'):
            name = form_input.get('name')
            if name:
                inputs.append(name)

    return inputs
